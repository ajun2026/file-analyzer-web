# 文件分析平台 (Dump Analyzer)

Windows 崩溃转储文件 (DMP/EVTX) 在线分析平台。上传压缩包自动解压，支持 DMP 解析、EVTX 日志分析、AI 问答。

## 功能特性

- **多格式上传**：ZIP / TAR.GZ / 7Z / RAR 自动解压
- **DMP 解析**：支持 Minidump (MDMP)、PAGEDU64 (Win10+)、完整内存转储 (Full Dump)
- **EVTX 分析**：自动提取系统日志中的 BugCheck 事件、硬件错误、驱动问题
- **AI 对话**：基于文件内容的流式 AI 问答（DeepSeek API）
- **大文件优化**：2GB+ 的 MEMORY.DMP 也能高效解析（仅读文件头 + evtx 关联）
- **GPU 检测**：自动识别 Intel/NVIDIA/AMD 显卡驱动问题

## 环境要求

| 组件 | 版本 | 说明 |
|------|------|------|
| Nginx | ≥1.18 | Web 服务器 |
| PHP | 8.1+ | 需 php-fpm, php-zip, php-mbstring, php-curl |
| Python | 3.10+ | 需 pip 安装 python-evtx |
| 7-Zip | 任意 | 解压 .7z 文件 |

```bash
# Ubuntu/Debian 安装依赖
apt install nginx php8.1-fpm php8.1-zip php8.1-mbstring php8.1-curl python3 python3-pip p7zip-full
pip3 install python-evtx
```

## 部署步骤

1. 将项目文件放置到 `/var/www/html/`
2. 创建上传目录并设置权限：

```bash
mkdir -p /var/www/html/uploads
chown -R www-data:www-data /var/www/html/uploads
chmod 755 /var/www/html/uploads
```

3. 配置 Nginx（示例）：

```nginx
server {
    listen 80;
    root /var/www/html;
    index index.html;
    client_max_body_size 200M;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
        fastcgi_buffering off;
        fastcgi_read_timeout 120s;
    }
}
```

4. 配置 chat.php 中的 DeepSeek API Key（第 123 行）：

```php
$apiKey = 'sk-your-api-key-here';
```

5. 重启服务：

```bash
systemctl restart nginx php8.1-fpm
```

## 项目结构

```
/var/www/html/
├── index.html              # 主页：文件上传
├── analysis.html            # 分析页：文件树 + 查看器 + AI 对话
├── css/
│   └── style.css            # 全局样式
├── js/
│   ├── main.js              # 主页逻辑（上传、列表、删除）
│   └── analysis.js          # 分析页逻辑（文件树、查看器、AI 对话、SSE）
└── api/
    ├── upload.php           # 文件上传 + 自动解压
    ├── delete.php           # 删除文件及解压内容
    ├── files.php            # 文件列表 API
    ├── filetree.php         # 文件树 API
    ├── read.php             # 读取文件内容（DMP/EVTX 走解析器）
    ├── download.php         # 下载原始压缩包
    ├── chat.php             # AI 对话 API (SSE 流式)
    ├── helpers.php          # 工具函数（编码检测、文件读取）
    ├── dmp_parser.py        # DMP 转储文件解析器（核心）
    └── evtx_parser.py       # EVTX 事件日志解析器
```

## DMP 解析器说明

`dmp_parser.py` 支持的转储格式：

| 格式 | 签名 | 说明 |
|------|------|------|
| MDMP | `MDMP` | 标准 Minidump，包含异常信息、模块列表、线程列表 |
| PAGEDU64 | `PAGEDU64` | Windows 10+ 自动/分类转储 |
| PAGEDUMP | `PAGEDUMP` | 完整内存转储 |
| DUMP | `DUMP` | 旧版内核转储 |

### BugCheck 检测策略（优先级从高到低）

1. **PAGEDU64 header offset 0x38** — Win11 自动转储的标准位置
2. **KDBG 块** — KDDEBUGGER_DATA64 结构体中的 BugCheck 字段
3. **System.evtx 事件 1001** — 从同目录 oslog/System.evtx 提取
4. **evtx 原始文本搜索** — 对大 evtx 文件用 head -c 快速搜索

### 支持分析的 BugCheck 代码

包括但不限于：IRQL (0xA, 0xD1), 内存管理 (0x1A, 0x50), 显卡 TDR (0x116-0x119, 0x141), WHEA (0x124), DPC 看门狗 (0x133), 关键进程 (0xEF), 内核安全 (0x139) 等 40+ 种常见崩溃代码。

### 大文件处理

| 文件大小 | 字符串提取策略 |
|----------|---------------|
| < 20 MB | `strings` 全量读取 |
| 20-100 MB | `strings` 全量 |
| > 100 MB | `head -c 5MB` 截断 + "header-only" 标记 |

BugCheck 信息始终从文件头/evtx 获取，不依赖全量字符串提取。

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `api/upload.php` | 上传文件（multipart/form-data） |
| GET | `api/files.php` | 获取文件列表 |
| GET | `api/filetree.php?id=<id>` | 获取文件树 |
| GET | `api/read.php?id=<id>&file=<path>` | 读取/解析文件内容 |
| GET | `api/download.php?id=<id>` | 下载原始压缩包 |
| POST | `api/delete.php` | 删除文件（JSON: {id}） |
| POST | `api/chat.php` | AI 流式对话（SSE） |

## 注意事项

- 上传大文件（>200MB）需调整 nginx `client_max_body_size` 和 PHP `upload_max_filesize`、`post_max_size`
- `chat.php` 中的 DeepSeek API Key 需自行申请配置
- 上传目录 `uploads/` 需要 www-data 写入权限
- 完整内存转储（>1GB）建议用 WinDbg 分析，本工具仅提供文件头级别的摘要
- DMP 文件名的日期格式为 `MMDDYY-XXXXX-YY.dmp`，解析器会利用此信息匹配 evtx 中的崩溃事件

## License

Internal use.
