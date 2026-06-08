<?php
// 判断文件是否为可读文本
function isReadableText($filePath) {
    static $textExtensions = [
        'txt', 'log', 'ini', 'cfg', 'conf', 'cnf', 'md', 'rst', 'csv', 'tsv',
        'json', 'xml', 'html', 'htm', 'xhtml', 'svg',
        'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs',
        'css', 'scss', 'sass', 'less',
        'py', 'pyw', 'pyx', 'evtx', 'dmp', 'hdmp', 'mdmp',
        'php', 'phtml', 'php3', 'php4', 'php5',
        'java', 'kt', 'kts', 'scala', 'groovy',
        'c', 'h', 'cpp', 'hpp', 'cc', 'hh', 'cxx', 'hxx',
        'cs', 'go', 'rs', 'rb', 'pl', 'pm', 'lua', 'r', 'swift',
        'sql', 'yaml', 'yml', 'toml', 'env', 'properties',
        'sh', 'bash', 'zsh', 'fish', 'bat', 'cmd', 'ps1',
        'dockerfile', 'makefile', 'cmake', 'nginx',
        'vim', 'vimrc', 'gitignore', 'gitconfig', 'editorconfig',
    ];
    
    $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    $filename = strtolower(pathinfo($filePath, PATHINFO_FILENAME));
    
    // 无扩展名但文件名是已知文本文件名
    $textFilenames = ['makefile', 'dockerfile', 'jenkinsfile', 'vagrantfile', 'gemfile', 'rakefile', 'procfile'];
    if (in_array($filename, $textFilenames)) return true;
    
    // MIME 白名单
    $textMimes = [
        'text/', 'application/json', 'application/xml', 'application/javascript',
        'application/x-httpd-php', 'application/x-yaml', 'application/x-sh',
        'application/x-sql', 'application/x-python', 'text/x-python',
        'application/x-wine-extension-ini', 'application/x-msdos-program',
        'application/x-msdownload', 'application/x-shellscript',
        'application/x-csh', 'application/x-ksh', 'application/x-tcl',
        'application/x-perl', 'application/x-ruby', 'application/x-lua',
        'message/rfc822', 'application/x-httpd-php-source',
        'application/x-pem-file', 'application/pkix-cert',
        'application/x-font-ttf',
    ];
    
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime = finfo_file($finfo, $filePath);
    finfo_close($finfo);
    
    foreach ($textMimes as $tm) {
        if (strpos($mime, $tm) === 0) return true;
    }
    
    // 扩展名回退
    if (in_array($ext, $textExtensions)) return true;
    
    // 最后手段：读前 512 字节，如果 90% 以上是可打印字符就当作文本
    $fh = fopen($filePath, 'rb');
    if (!$fh) return false;
    $sample = fread($fh, 512);
    fclose($fh);
    if ($sample === false || strlen($sample) === 0) return false;
    
    $printable = 0;
    $total = strlen($sample);
    for ($i = 0; $i < $total; $i++) {
        $c = ord($sample[$i]);
        if (($c >= 0x20 && $c <= 0x7E) || $c === 0x0A || $c === 0x0D || $c === 0x09) {
            $printable++;
        }
    }
    return ($printable / $total) > 0.90;
}

// 自动检测编码并转为 UTF-8（通用函数）
function ensureUtf8($content) {
    if (empty($content)) return $content;
    $encoding = mb_detect_encoding($content, ['UTF-8', 'GBK', 'GB2312', 'GB18030', 'BIG5', 'ISO-8859-1', 'Windows-1252', 'ASCII'], true);
    if ($encoding && $encoding !== 'UTF-8' && $encoding !== 'ASCII') {
        $converted = mb_convert_encoding($content, 'UTF-8', $encoding);
        if ($converted !== false) $content = $converted;
    }
    // 兜底：清除残留的无效 UTF-8 字节
    return mb_convert_encoding($content, 'UTF-8', 'UTF-8');
}

// 读取文件内容（支持 evtx 等特殊格式转换）
function readFileContent($filePath) {
    static $evtxCount = 0;
    $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    
    // dmp: Windows 内存转储文件解析
    if (in_array($ext, ['dmp', 'hdmp', 'mdmp'])) {
        $parser = __DIR__ . '/dmp_parser.py';
        $cmd = sprintf('python3 %s %s 2>/dev/null',
            escapeshellarg($parser),
            escapeshellarg($filePath)
        );
        $json = shell_exec($cmd);
        if ($json) {
            $data = json_decode($json, true);
            if ($data && isset($data['text'])) {
                return "[DMP 内存转储分析报告]\n" . $data['text'];
            }
            if ($data && isset($data['error'])) {
                return "[DMP 解析失败: {$data['error']}]";
            }
        }
        return "[无法解析 DMP 文件: {$filePath}]";
    }
    
    // evtx: 只解析前 5 个关键文件，其余跳过
    if ($ext === 'evtx') {
        $keyEvtxFiles = ['System.evtx', 'Application.evtx', 'Security.evtx',
            'Microsoft-Windows-WER-Diag%4Operational.evtx',
            'Microsoft-Windows-Kernel-PnP%4Driver Watchdog.evtx',
            'Microsoft-Windows-Kernel-Power%4Thermal-Operational.evtx'];
        $fname = basename($filePath);
        
        $isKey = in_array($fname, $keyEvtxFiles) || $evtxCount < 3;
        if (!$isKey) {
            return "[EVTX 跳过: {$fname} (仅解析关键日志文件)]";
        }
        $evtxCount++;
        $parser = __DIR__ . '/evtx_parser.py';
        $cmd = sprintf('python3 %s %s 0 2>/dev/null',
            escapeshellarg($parser),
            escapeshellarg($filePath)
        );
        $json = shell_exec($cmd);
        if ($json) {
            $data = json_decode($json, true);
            if ($data && isset($data['text'])) {
                return "[EVTX 解析 - 近{$data['months']}个月, {$data['in_range']}条事件, 硬件错误{$data['hardware_errors']}条, 展示{$data['shown']}条]\n" . $data['text'];
            }
        }
        return "[无法解析 evtx 文件: {$filePath}]";
    }
    
    // 普通文本文件：自动检测编码并转换为 UTF-8
    if (!is_readable($filePath)) return false;
    $content = file_get_contents($filePath);
    if ($content === false) return false;
    return ensureUtf8($content);
}
