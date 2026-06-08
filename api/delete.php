<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['error' => '仅支持 POST 请求']);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$id = $input['id'] ?? ($_POST['id'] ?? '');

if (!$id) {
    echo json_encode(['error' => '缺少文件 ID']);
    exit;
}

$id = basename($id); // 安全：防止路径穿越
$targetDir = __DIR__ . '/../uploads/' . $id;

if (!is_dir($targetDir)) {
    echo json_encode(['success' => true, 'message' => '目录已不存在']);
    exit;
}

// 递归删除目录
function deleteDir($dir) {
    if (!is_dir($dir)) return false;
    $items = scandir($dir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . '/' . $item;
        if (is_dir($path)) {
            deleteDir($path);
        } else {
            unlink($path);
        }
    }
    return rmdir($dir);
}

if (deleteDir($targetDir)) {
    echo json_encode(['success' => true, 'message' => '已删除']);
} else {
    echo json_encode(['error' => '删除失败，请检查权限']);
}
