<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
require_once __DIR__ . '/helpers.php';

$id = $_GET['id'] ?? '';
$file = $_GET['file'] ?? '';

if (!$id || !$file) {
    echo json_encode(['error' => '缺少参数']);
    exit;
}

$basePath = __DIR__ . '/../uploads/' . basename($id) . '/extracted/';
$filePath = $basePath . $file;

// 安全检查，防止路径穿越
$realBase = realpath($basePath);
$realFile = realpath($filePath);
if (!$realFile || strpos($realFile, $realBase) !== 0) {
    echo json_encode(['error' => '文件不存在或路径非法']);
    exit;
}

// 检查文件是否可读
if (!is_readable($realFile)) {
    echo json_encode(['error' => '文件不可读']);
    exit;
}

// 特殊格式文件（DMP/EVTX）走解析器
$ext = strtolower(pathinfo($realFile, PATHINFO_EXTENSION));
if (in_array($ext, ['dmp', 'hdmp', 'mdmp', 'evtx'])) {
    $fileSize = filesize($realFile);
    $content = readFileContent($realFile);
    if ($content === false) {
        echo json_encode(['error' => '无法解析文件']);
        exit;
    }
    if (strlen($content) > 1024 * 1024) {
        $content = substr($content, 0, 1024 * 1024) . "\n\n... [内容过长，已截断]";
    }
    echo json_encode([
        'name' => $file,
        'size' => $fileSize,
        'content' => $content
    ], JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    exit;
}

// HTML 文件：始终通过 iframe 嵌入渲染
$ext = strtolower(pathinfo($realFile, PATHINFO_EXTENSION));
if (in_array($ext, ['html', 'htm'])) {
    $fileSize = filesize($realFile);
    echo json_encode([
        'name' => $file,
        'size' => $fileSize,
        'html_view' => true,
        'serve_url' => 'api/serve.php?id=' . urlencode($id) . '&file=' . urlencode($file)
    ]);
    exit;
}

$fileSize = filesize($realFile);

// 大文本文件（>5MB）：走 serve.php 流式输出，避免 JSON 内存爆炸
if ($fileSize > 5 * 1024 * 1024) {
    $readable = isReadableText($realFile);
    if ($readable) {
        echo json_encode([
            'name' => $file,
            'size' => $fileSize,
            'stream_view' => true,
            'serve_url' => 'api/serve.php?id=' . urlencode($id) . '&file=' . urlencode($file)
        ]);
    } else {
        echo json_encode([
            'error' => '文件过大(' . round($fileSize / (1024 * 1024), 1) . 'MB > 5MB)，请下载后本地查看',
            'name' => $file,
            'size' => $fileSize
        ]);
    }
    exit;
}

// 读取原始内容
$content = file_get_contents($realFile);
if ($content === false) {
    echo json_encode(['error' => '无法读取文件']);
    exit;
}

$encoding = mb_detect_encoding($content, ['UTF-8', 'GBK', 'GB2312', 'GB18030', 'BIG5', 'ISO-8859-1', 'Windows-1252', 'ASCII'], true);
if ($encoding && $encoding !== 'UTF-8' && $encoding !== 'ASCII') {
    $converted = mb_convert_encoding($content, 'UTF-8', $encoding);
    if ($converted !== false) {
        $content = $converted;
    }
}

$content = mb_convert_encoding($content, 'UTF-8', 'UTF-8');

$maxLen = 500 * 1024;
if (strlen($content) > $maxLen) {
    $content = substr($content, 0, $maxLen) . "\n\n... [文件过大，已截断，完整大小: " . round($fileSize / 1024, 1) . " KB]";
}

echo json_encode([
    'name' => $file,
    'size' => $fileSize,
    'content' => $content
], JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
