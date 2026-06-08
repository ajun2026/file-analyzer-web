<?php
// AI 对话 API - SSE 流式响应
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');
header('Access-Control-Allow-Origin: *');
header('X-Accel-Buffering: no');
require_once __DIR__ . '/helpers.php'; // 禁用 nginx 缓冲

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
if (!$input || !isset($input['id']) || !isset($input['message'])) {
    echo "data: " . json_encode(['error' => '缺少参数']) . "\n\n";
    echo "data: [DONE]\n\n";
    exit;
}

$id = basename($input['id']);
$message = $input['message'];
$history = $input['history'] ?? [];

$basePath = __DIR__ . '/../uploads/' . $id . '/extracted/';

// 加载文件内容作为上下文
$filesContext = '';
if (is_dir($basePath)) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($basePath, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    
    // 第一遍：收集所有文件名，按目录分组
    $dirGroups = [];
    foreach ($iterator as $f) {
        if (!$f->isFile()) continue;
        $relPath = str_replace($basePath, '', $f->getPathname());
        $dir = dirname($relPath);
        if (!isset($dirGroups[$dir])) $dirGroups[$dir] = [];
        $dirGroups[$dir][] = basename($relPath);
    }
    
    // 文件清单——按目录分组展示，每目录最多 15 个文件名
    $totalFiles = 0;
    $filesContext = "【文件清单】\n";
    ksort($dirGroups);
    foreach ($dirGroups as $dir => $files) {
        sort($files);
        $totalFiles += count($files);
        $filesContext .= "\n📁 {$dir}/ (" . count($files) . " 个文件)\n";
        $show = array_slice($files, 0, 15);
        foreach ($show as $f) {
            $filesContext .= "    - {$f}\n";
        }
        if (count($files) > 15) {
            $filesContext .= "    ... 还有 " . (count($files) - 15) . " 个\n";
        }
    }
    $filesContext .= "\n总计: {$totalFiles} 个文件\n\n【部分文件内容摘要】\n";
    
    // 第二遍：收集可读文件路径
    $textPaths = [];
    foreach ($iterator as $f) {
        if (!$f->isFile()) continue;
        if (!isReadableText($f->getPathname())) continue;
        $textPaths[] = $f->getPathname();
    }
    
    // 优先排序：BMC 关键日志 > 重要日志 > 其他日志 > 普通文件
    $bmcCritical = ['bmc-err.log', 'kernel-err.log', 'ffdc.log', 'component_activity.log',
        'kernel.log', 'bmc-warn.log', 'xcc_pl_error.log', 'pfr_device.log'];
    $bmcImportant = ['syshealth.log', 'security.log', 'system.log', 'bmc-loop.log',
        'syshealth-crit.log', 'security.boot.log', 'hostlog.log', 'ffdc_live_dbg'];
    
    usort($textPaths, function($a, $b) use ($basePath, $bmcCritical, $bmcImportant) {
        $aBase = basename($a); $bBase = basename($b);
        // 优先级分组：0=关键BMC日志 1=重要BMC日志 2=其他.log 3=普通
        $aPri = in_array($aBase, $bmcCritical) ? 0 : (in_array($aBase, $bmcImportant) ? 1 :
            (str_ends_with(strtolower($aBase), '.log') ? 2 : 3));
        $bPri = in_array($bBase, $bmcCritical) ? 0 : (in_array($bBase, $bmcImportant) ? 1 :
            (str_ends_with(strtolower($bBase), '.log') ? 2 : 3));
        if ($aPri !== $bPri) return $aPri - $bPri;
        // 同优先级按深度排（浅目录优先）
        $aDepth = substr_count(str_replace($basePath, '', $a), '/');
        $bDepth = substr_count(str_replace($basePath, '', $b), '/');
        if ($aDepth !== $bDepth) return $aDepth - $bDepth;
        return strcmp($a, $b);
    });
    
    // 加载内容：关键文件 10KB，普通文件 5KB，总上限 1.5MB（DeepSeek 1M tokens 约 3MB，留一半余量）
    $totalChars = strlen($filesContext);
    $maxChars = 1500000;
    
    foreach ($textPaths as $path) {
        if ($totalChars >= $maxChars) break;
        $relPath = str_replace($basePath, '', $path);
        $isKeyFile = in_array(basename($path), array_merge($bmcCritical, $bmcImportant));
        $perFileMax = $isKeyFile ? 10240 : 5120;
        
        $content = readFileContent($path);
        if ($content === false) continue;
        $chunk = mb_substr($content, 0, min($perFileMax, $maxChars - $totalChars));
        $filesContext .= "\n=== {$relPath} ===\n{$chunk}\n";
        $totalChars += strlen($chunk) + strlen($relPath) + 20;
    }
}

// 构建 messages
$systemPrompt = "你是一个专业的文件分析助手。用户上传了一批文件，你需要基于这些文件内容来回答用户的问题。\n\n以下是上传文件的内容摘要：\n{$filesContext}\n\n请基于以上文件内容，用中文回答用户的问题。如果问题与文件内容无关，可以结合你的知识回答。回答要清晰、结构化。";

$messages = [
    ['role' => 'system', 'content' => $systemPrompt]
];

// 添加历史对话（最多保留最近 10 轮）
$recentHistory = array_slice($history, -20);
foreach ($recentHistory as $h) {
    $messages[] = ['role' => $h['role'], 'content' => $h['content']];
}

// 添加当前消息
$messages[] = ['role' => 'user', 'content' => $message];

// 调用 DeepSeek API
require_once __DIR__ . '/config.php';
$apiKey = DEEPSEEK_API_KEY;
$apiUrl = DEEPSEEK_API_URL;

$payload = json_encode([
    'model' => DEEPSEEK_MODEL,
    'messages' => $messages,
    'stream' => true,
    'temperature' => 0.7,
    'max_tokens' => 8192
], JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

$errorBody = '';
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL => $apiUrl,
    CURLOPT_POST => true,
    CURLOPT_POSTFIELDS => $payload,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer ' . $apiKey,
        'Content-Type: application/json',
        'Accept: text/event-stream'
    ],
    CURLOPT_RETURNTRANSFER => false,
    CURLOPT_TIMEOUT => 120,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_WRITEFUNCTION => function($ch, $data) use (&$errorBody) {
        $errorBody .= $data;
        // DeepSeek 返回的是 SSE 格式，直接转发
        $lines = explode("\n", $data);
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            if (strpos($line, 'data: ') === 0) {
                $jsonStr = substr($line, 6);
                if ($jsonStr === '[DONE]') {
                    echo "data: [DONE]\n\n";
                } else {
                    $chunk = json_decode($jsonStr, true);
                    if ($chunk && isset($chunk['choices'][0]['delta']['content'])) {
                        $text = $chunk['choices'][0]['delta']['content'];
                        echo "data: " . json_encode(['content' => $text]) . "\n\n";
                    }
                }
                ob_flush();
                flush();
            }
        }
        return strlen($data);
    }
]);

curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
curl_close($ch);

if ($error) {
    echo "data: " . json_encode(['error' => 'API 请求失败: ' . $error]) . "\n\n";
    echo "data: [DONE]\n\n";
} elseif ($httpCode !== 200) {
    // 解析错误响应
    $errMsg = 'API 返回错误，状态码: ' . $httpCode;
    $errJson = json_decode($errorBody, true);
    if ($errJson && isset($errJson['error']['message'])) {
        $errMsg = $errJson['error']['message'];
    }
    echo "data: " . json_encode(['error' => $errMsg . ' (状态码:' . $httpCode . ')']) . "\n\n";
    echo "data: [DONE]\n\n";
}
