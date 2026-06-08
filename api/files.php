<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
require_once __DIR__ . '/helpers.php';

$uploadsDir = __DIR__ . '/../uploads/';
$dirs = array_filter(glob($uploadsDir . '*'), 'is_dir');
$items = [];

foreach ($dirs as $dir) {
    $id = basename($dir);
    $originalFile = '';
    $originalSize = 0;
    $extracted = is_dir($dir . '/extracted');
    
    // 找原始文件（跳过 extracted 目录和 _meta.json 缓存）
    foreach (glob($dir . '/*') as $f) {
        if (is_file($f) && basename($f) !== 'extracted' && basename($f) !== '_meta.json') {
            $originalFile = basename($f);
            $originalSize = filesize($f);
            break;
        }
    }
    
    // 统计解压后文件（优先读缓存，避免每次遍历数千文件）
    $totalFiles = 0;
    $textFiles = 0;
    if ($extracted) {
        $metaFile = $dir . '/_meta.json';
        if (file_exists($metaFile)) {
            $meta = json_decode(file_get_contents($metaFile), true);
            $totalFiles = $meta['total_files'] ?? 0;
            $textFiles = $meta['text_files'] ?? 0;
        } else {
            // 缓存不存在时才扫描（首次或缓存被清理后）
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir . '/extracted', RecursiveDirectoryIterator::SKIP_DOTS)
            );
            foreach ($iterator as $f) {
                if ($f->isFile()) {
                    $totalFiles++;
                    if (isReadableText($f->getPathname())) $textFiles++;
                }
            }
            // 生成缓存
            file_put_contents($metaFile, json_encode([
                'total_files' => $totalFiles,
                'text_files' => $textFiles
            ]));
        }
    }
    
    $items[] = [
        'id' => $id,
        'name' => $originalFile,
        'size' => $originalSize,
        'extracted' => $extracted,
        'total_files' => $totalFiles,
        'text_files' => $textFiles,
        'created' => date('Y-m-d H:i:s', filemtime($dir))
    ];
}

// 按时间倒序
usort($items, function($a, $b) {
    return strcmp($b['created'], $a['created']);
});

echo json_encode($items);
