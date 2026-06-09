# Log Analyzer — 日志诊断分析平台

统一的日志诊断分析系统，支持 **Windows 蓝屏诊断**、**Linux 系统日志**、**BMC/XCC 服务器日志** 三类日志包的自动识别、结构化分析和 AI 辅助诊断。

> 原 PHP 版保留在 [`php-legacy`](../../tree/php-legacy) 分支。重构前快照：`v3.0-monolith` tag。

---

## 项目结构

```
log-analyzer/
├── main.py                     # FastAPI 入口 + 路由 (539行)
├── detectors.py                # OS检测 / 解压 / 编码 / 历史管理
├── analyzers/
│   ├── dump_parser.py          # DMP解析 + 74种BugCheck码表
│   ├── windows.py              # Windows 6项诊断分析
│   └── linux.py                # Linux 4项诊断分析
├── chat/
│   ├── function_call.py        # FC模式 (Win/Linux): 工具调用链
│   └── context_inject.py       # 上下文注入 (BMC/Other): 一次调用
├── templates/
│   ├── upload.html             # 上传页 + 历史 (含 BMC 徽章)
│   ├── analyze.html            # 分析页 (三分支布局)
│   └── report.html             # 单报告页 (遗留)
└── requirements.txt
```

---

## 功能特性

### 三类日志自动分流

| 类型 | 检测特征 | 分析布局 | AI 聊天模式 |
|------|---------|---------|------------|
| 🪟 Windows | `tslog/` / `oslog/` / `.evtx` / `.dmp` | 6 标签页结构化诊断 | Function Calling |
| 🐧 Linux | `var/log/` / `syslog` / `kern.log` | 5 标签页结构化诊断 | Function Calling |
| 🔧 BMC/XCC | `ffdc.log` / `.tzz` 格式 / BMC 特征文件 | 文件浏览器 + AI 对话 | 上下文注入 (秒级) |

### Windows 诊断（6 标签页）

| 标签 | 功能 | 数据来源 |
|------|------|---------|
| 📄 系统概览 | CPU/GPU/磁盘/NIC/SIO 硬件信息 | Systeminfo.txt, dxdiag.txt, SMARTINFO.txt |
| 📋 系统诊断 | BugCheck 蓝屏、意外断电、LiveKernelEvent、硬件告警、安装崩溃关联 | System.evtx, Application.evtx |
| 💾 Dump 分析 | 蓝屏转储文件深度解析 | osdump/*.dmp |
| 📋 SIOlog | Lenovo SIO/EC 控制器事件 | SIO_Events.log |
| 📊 整体总结 | 综合评分 + 严重性评估 + 行动建议 | 汇总以上 |
| 🤖 AI 分析 | DeepSeek 工具调用链分析 | 全部文件 |

### Linux 诊断（5 标签页）

| 标签 | 功能 | 数据来源 |
|------|------|---------|
| 📄 系统概览 | OS 版本、CPU、内存、磁盘 | /etc/os-release, /proc/cpuinfo, /proc/meminfo |
| 🔧 内核诊断 | OOM killer、kernel panic/oops、硬件错误 (MCE/PCIe/ATA) | kern.log, dmesg |
| 📋 系统日志 | 服务失败、认证失败 (暴力破解)、磁盘 I/O、网络错误 | syslog, messages |
| 📊 整体总结 | 严重性评估 + 发现汇总 | 汇总以上 |
| 🤖 AI 分析 | DeepSeek 工具调用链分析 | 全部文件 |

### BMC/XCC 诊断（NEW — 借鉴 file-analyzer-web）

- 支持 `.tzz` 格式 (IBM/Lenovo XCC FFDC，`tar --lzop` 解压)
- 支持双层压缩自动解压 (`.tar.gz` 内含 `.tzz`)
- 文件浏览器 + AI 聊天双栏布局
- 上下文注入模式：自动加载所有日志文件，**秒级 AI 响应**
- BMC 关键日志智能排序（`bmc-err.log` > `syshealth.log` > 普通 `.log`）
- 1.5MB 上下文上限，充分利用 DeepSeek 1M token 窗口

### AI 对话

| 模式 | 适用场景 | 原理 | 响应速度 |
|------|---------|------|---------|
| Function Calling | Windows / Linux | AI 主动调工具 (list_files → read_dump → read_evtx) 多步推理 | 2-4 分钟 |
| 上下文注入 | BMC / Other | 遍历所有可读文件 → 拼入 system prompt → 一次 API 调用 | 秒级 |

### 其他特性

- 拖拽上传 + 主机 SN 模态确认（防跨用户 SN 泄漏）
- 文件树浏览器 + 文本/DMP 内联预览
- 历史记录管理（上传/下载/删除）
- 暗色主题 UI（`#0d1117` 背景）

---

## DMP 解析器

`analyzers/dump_parser.py` 支持的转储格式：

| 格式 | 签名 | 说明 |
|------|------|------|
| MDMP | `MDMP` | 标准 Minidump，包含异常信息、模块列表、线程列表 |
| PAGEDU64 | `PAGEDU64` | Windows 10+ 自动/分类转储 |
| PAGEDUMP | `PAGEDUMP` | 完整内存转储 |
| DUMP / DU64 / PAGE | `DUMP` / `DU64` / `PAGE` | 旧版内核/完整转储 |

### BugCheck 检测策略（优先级从高到低）

1. **PAGEDU64 header offset 0x38** — Win11 自动转储的标准位置
2. **KDBG 块** — KDDEBUGGER_DATA64 结构体中的 BugCheck 字段
3. **System.evtx 事件 1001** — 从同目录 System.evtx 精确匹配
4. **文件名日期匹配** — DMP 文件名 `MMDDYY-XXXXX-YY.dmp` 匹配 evtx 时间

### 支持的 BugCheck 代码（74 种）

包括但不限于：IRQL (0xA, 0xD1), 内存管理 (0x1A, 0x50), 显卡 TDR (0x116-0x119, 0x141), WHEA (0x124), DPC 看门狗 (0x133), 关键进程 (0xEF), 内核安全 (0x139), 驱动电源 (0x9F) 等，全部含中文解释。

### 大文件处理

| 文件大小 | 策略 |
|----------|------|
| 0 字节 | 跳过 |
| > 0 | 读取文件头 0x200 字节，BugCheck 从 header/evtx 获取 |
| 完整转储 (>1GB) | 仅提供文件头摘要，建议 WinDbg 深度分析 |

---

## 环境要求

| 组件 | 版本 | 说明 |
|------|------|------|
| Python | 3.10+ | 需 pip 安装依赖 |
| Nginx | ≥1.18 | 反向代理 |
| 7-Zip | 任意 | `.7z` 解压 |
| unrar | 任意 | `.rar` 解压 |
| lzop | 任意 | `.tzz` 解压 (IBM XCC FFDC) |

```bash
# Ubuntu/Debian 安装系统依赖
apt install nginx python3 python3-pip p7zip-full unrar lzop

# 安装 Python 依赖
pip install -r requirements.txt
```

---

## 部署步骤

### 1. 克隆项目

```bash
git clone https://github.com/ajun2026/file-analyzer-web.git /opt/log-analyzer
```

### 2. 配置 DeepSeek API Key

编辑 `chat/function_call.py`：

```python
DEEPSEEK_API_KEY = "sk-your-deepseek-api-key"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
```

### 3. 创建上传目录

```bash
mkdir -p /opt/log-analyzer/uploads /opt/log-analyzer/reports
chown -R www-data:www-data /opt/log-analyzer/uploads /opt/log-analyzer/reports
```

### 4. 配置 Nginx

```nginx
server {
    listen 80;
    client_max_body_size 500M;

    location /log-analyzer/ {
        proxy_pass http://127.0.0.1:8002/;
        proxy_read_timeout 300s;
        proxy_connect_timeout 30s;
        proxy_send_timeout 60s;
    }
}
```

### 5. 启动服务

```bash
# 手动启动
cd /opt/log-analyzer && python3 main.py

# 或使用 systemd
cat > /etc/systemd/system/log-analyzer.service << 'EOF'
[Unit]
Description=Log Analyzer
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/opt/log-analyzer
ExecStart=python3 main.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable --now log-analyzer
```

---

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/` | 上传首页 |
| GET | `/analyze/{job_id}` | 分析中心（三分支布局） |
| POST | `/api/upload` | 上传文件 (multipart/form-data + sn) |
| POST | `/api/analyze/{job_id}?analysis_type=X` | 触发指定类型分析 |
| GET | `/api/status/{job_id}` | 轮询分析进度 |
| GET | `/api/report/{job_id}?type=X` | 获取分析报告 JSON |
| GET | `/api/files/{job_id}` | 文件树 JSON |
| GET | `/api/file-content/{job_id}?path=P` | 读文本/解析 DMP |
| POST | `/api/chat/{job_id}` | AI 对话 (FC / 上下文注入) |
| GET | `/api/download/{job_id}` | 下载原始压缩包 |
| DELETE | `/api/job/{job_id}` | 删除任务及关联文件 |
| GET | `/api/history` | 历史记录列表 |

---

## 更新日志

### v3.1 (2026-06-09) — 模块化重构

- 2900 行单文件 `main.py` 拆分为 7 个模块
- 清晰的目录结构：`analyzers/` + `chat/` + `detectors.py`
- 首页系统类型徽章（🪟 Windows / 🐧 Linux / 🔧 BMC）

### v3.0 (2026-06-09) — 合并 file-analyzer-web

- BMC/XCC 日志检测（`find_log_dir` 新增 `bmc`/`other` 返回类型）
- `.tzz` 格式解压支持 + 双层压缩自动解压
- BMC/Other 新布局：文件浏览器 + AI 聊天下半区
- AI 聊天分流：Win/Linux → FC 模式，BMC/Other → 上下文注入模式
- 上下文注入：BMC 关键日志智能排序 + 1.5MB 上限

---

## License

Internal use.
