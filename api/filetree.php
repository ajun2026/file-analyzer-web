<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
require_once __DIR__ . '/helpers.php';

$id = $_GET['id'] ?? '';
if (!$id) {
    echo json_encode(['error' => '缺少参数']);
    exit;
}

$basePath = __DIR__ . '/../uploads/' . basename($id) . '/extracted/';
if (!is_dir($basePath)) {
    echo json_encode(['error' => '目录不存在']);
    exit;
}

function scanDirRecursive($dir, $prefix = '') {
    $result = [];
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . '/' . $item;
        $relPath = $prefix . $item;
        if (is_dir($path)) {
            $children = scanDirRecursive($path, $relPath . '/');
            $result[] = [
                'name' => $item,
                'path' => $relPath,
                'type' => 'dir',
                'children' => $children
            ];
        } else {
            $readable = isReadableText($path);
            $result[] = [
                'name' => $item,
                'path' => $relPath,
                'type' => 'file',
                'size' => filesize($path),
                'readable' => $readable
            ];
        }
    }
    // 排序：目录在前，文件在后
    usort($result, function($a, $b) {
        if ($a['type'] !== $b['type']) return $a['type'] === 'dir' ? -1 : 1;
        return strcasecmp($a['name'], $b['name']);
    });
    return $result;
}

echo json_encode(scanDirRecursive($basePath));
