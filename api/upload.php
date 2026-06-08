<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !isset($_FILES['file'])) {
    echo json_encode(['error' => '请上传文件']);
    exit;
}

$file = $_FILES['file'];
if ($file['error'] !== UPLOAD_ERR_OK) {
    echo json_encode(['error' => '上传失败，错误码: ' . $file['error']]);
    exit;
}

// 生成唯一ID
$id = uniqid('file_', true);
$uploadDir = __DIR__ . '/../uploads/' . $id;
mkdir($uploadDir, 0777, true);

// 保存原始文件
$originalName = $file['name'];
$originalPath = $uploadDir . '/' . $originalName;
move_uploaded_file($file['tmp_name'], $originalPath);

// 自动解压
$extracted = false;
$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
$extractDir = $uploadDir . '/extracted';
mkdir($extractDir, 0777, true);

try {
    if ($ext === 'zip') {
        $zip = new ZipArchive();
        if ($zip->open($originalPath) === true) {
            $zip->extractTo($extractDir);
            $zip->close();
            $extracted = true;
        }
    } elseif (in_array($ext, ['tar', 'gz', 'bz2', 'xz', 'tgz', 'tbz2'])) {
        // 使用 tar 命令
        $cmd = sprintf('tar -xf %s -C %s 2>&1', escapeshellarg($originalPath), escapeshellarg($extractDir));
        exec($cmd, $output, $ret);
        $extracted = ($ret === 0);
    } elseif ($ext === '7z') {
        $cmd = sprintf('7z x %s -o%s -y 2>&1', escapeshellarg($originalPath), escapeshellarg($extractDir));
        exec($cmd, $output, $ret);
        $extracted = ($ret === 0);
    } elseif ($ext === 'rar') {
        $cmd = sprintf('unrar x %s %s 2>&1', escapeshellarg($originalPath), escapeshellarg($extractDir));
        exec($cmd, $output, $ret);
        $extracted = ($ret === 0);
    } elseif ($ext === 'tzz') {
        // tzz: lzop 压缩的 tar 包 (IBM/Lenovo XCC FFDC 格式)
        $cmd = sprintf('tar --lzop -xf %s -C %s 2>&1', escapeshellarg($originalPath), escapeshellarg($extractDir));
        exec($cmd, $output, $ret);
        $extracted = ($ret === 0);
    }
    // 修复解压文件权限，确保 Web 用户可读
    exec('chmod -R a+r ' . escapeshellarg($extractDir) . ' 2>/dev/null');
} catch (Exception $e) {
    $extracted = false;
}

// 统计文件信息
$totalFiles = 0;
$totalSize = 0;
$fileList = [];
$textFiles = 0;

if ($extracted && is_dir($extractDir)) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($extractDir, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    foreach ($iterator as $f) {
        if ($f->isFile()) {
            $totalFiles++;
            $totalSize += $f->getSize();
            $fileList[] = [
                'name' => str_replace($extractDir . '/', '', $f->getPathname()),
                'size' => $f->getSize()
            ];
            // 检查是否为可读文本文件
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $f->getPathname());
            finfo_close($finfo);
            if (strpos($mime, 'text/') === 0 || in_array($mime, [
                'application/json', 'application/xml', 'application/javascript',
                'application/x-httpd-php', 'application/x-yaml', 'application/x-sh'
            ])) {
                $textFiles++;
            }
        }
    }
}

echo json_encode([
    'success' => true,
    'id' => $id,
    'name' => $originalName,
    'size' => $file['size'],
    'extracted' => $extracted,
    'total_files' => $totalFiles,
    'total_size' => $totalSize,
    'text_files' => $textFiles,
    'file_list' => $fileList
]);
