<?php
// 下载原始上传文件
$id = $_GET['id'] ?? '';

if (!$id) {
    http_response_code(400);
    echo '缺少参数';
    exit;
}

$id = basename($id);
$uploadsDir = __DIR__ . '/../uploads/' . $id . '/';
if (!is_dir($uploadsDir)) {
    http_response_code(404);
    echo '文件不存在';
    exit;
}

// 找原始压缩包文件（排除 extracted 目录）
$originalFile = null;
foreach (glob($uploadsDir . '*') as $f) {
    if (is_file($f) && basename($f) !== 'extracted') {
        $originalFile = $f;
        break;
    }
}

if (!$originalFile) {
    http_response_code(404);
    echo '未找到原始文件';
    exit;
}

$filename = basename($originalFile);
$filesize = filesize($originalFile);

// 设置下载头
header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Content-Length: ' . $filesize);
header('Access-Control-Allow-Origin: *');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

// 大文件分段输出
$handle = fopen($originalFile, 'rb');
if (!$handle) {
    http_response_code(500);
    echo '无法打开文件';
    exit;
}

while (!feof($handle)) {
    echo fread($handle, 8192);
    ob_flush();
    flush();
}
fclose($handle);
