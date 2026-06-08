<?php
/**
 * 直接输出提取文件的原始内容（用于 iframe 嵌入 HTML 等）
 * 自动检测编码并设置正确的 charset，不做转换避免破坏二进制数据
 */
$id = $_GET['id'] ?? '';
$file = $_GET['file'] ?? '';

if (!$id || !$file) {
    http_response_code(400);
    echo '缺少参数';
    exit;
}

$basePath = __DIR__ . '/../uploads/' . basename($id) . '/extracted/';
$filePath = $basePath . $file;

// 安全检查：防止路径穿越
$realBase = realpath($basePath);
$realFile = realpath($filePath);
if (!$realFile || strpos($realFile, $realBase) !== 0) {
    http_response_code(404);
    echo '文件不存在';
    exit;
}

if (!is_readable($realFile)) {
    http_response_code(403);
    echo '文件不可读';
    exit;
}

$filesize = filesize($realFile);
$content = file_get_contents($realFile);
if ($content === false) {
    http_response_code(500);
    echo '无法读取文件';
    exit;
}

$ext = strtolower(pathinfo($realFile, PATHINFO_EXTENSION));

// 检测实际编码
$encoding = null;
$textExts = ['html', 'htm', 'txt', 'log', 'xml', 'csv', 'md', 'json', 'svg', 'css', 'js'];
if (in_array($ext, $textExts)) {
    $encoding = mb_detect_encoding($content, ['UTF-8', 'GBK', 'GB2312', 'GB18030', 'BIG5', 'ASCII'], true);
    
    // 未检测到或 ASCII 但含非 ASCII 字节 → 很可能是 GBK
    if (!$encoding || $encoding === 'ASCII') {
        $sampleLen = min(strlen($content), 65536);
        $hasHighBytes = false;
        for ($i = 0; $i < $sampleLen; $i++) {
            if (ord($content[$i]) > 0x7F) { $hasHighBytes = true; break; }
        }
        if ($hasHighBytes) $encoding = 'GBK';
    }

    // 如果是 GBK 编码且文件没有声明 charset，添加 <meta charset="GBK">
    if (in_array($encoding, ['GBK', 'GB2312', 'GB18030']) && in_array($ext, ['html', 'htm'])) {
        if (!preg_match('/<meta[^>]+charset/i', $content)) {
            $content = preg_replace(
                '/(<head[^>]*>)/i',
                '${1}' . "\n" . '<meta charset="GBK">',
                $content,
                1
            );
            if (strpos($content, 'charset') === false) {
                // No <head> tag, add at top
                $content = '<head><meta charset="GBK"></head>' . $content;
            }
        }
    }
}

// 根据编码设置正确的 Content-Type
$charset = 'utf-8';
if (in_array($encoding, ['GBK', 'GB2312', 'GB18030'])) {
    $charset = 'gbk';
} elseif ($encoding === 'BIG5') {
    $charset = 'big5';
}

$mimeTypes = [
    'html' => "text/html; charset=$charset",
    'htm'  => "text/html; charset=$charset",
    'css'  => "text/css; charset=$charset",
    'js'   => "application/javascript; charset=$charset",
    'json' => "application/json; charset=$charset",
    'xml'  => "application/xml; charset=$charset",
    'svg'  => 'image/svg+xml',
    'txt'  => "text/plain; charset=$charset",
    'log'  => "text/plain; charset=$charset",
    'md'   => "text/plain; charset=$charset",
    'csv'  => "text/csv; charset=$charset",
    'png'  => 'image/png',
    'jpg'  => 'image/jpeg',
    'jpeg' => 'image/jpeg',
    'gif'  => 'image/gif',
    'webp' => 'image/webp',
    'pdf'  => 'application/pdf',
];
$mime = $mimeTypes[$ext] ?? "text/plain; charset=$charset";

header('Content-Type: ' . $mime);
header('Content-Length: ' . strlen($content));
header('Access-Control-Allow-Origin: *');
header('Cache-Control: no-store, must-revalidate');
header('Pragma: no-cache');

echo $content;
