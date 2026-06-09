# 日志诊断分析平台 (Log Analyzer)

统一的日志诊断分析系统，支持 **Windows 蓝屏诊断**、**Linux 系统日志**、**BMC/XCC 服务器日志** 三类日志包的自动识别和分析。

> 本项目合并了 [file-analyzer-web](https://github.com/ajun2026/file-analyzer-web) (PHP) 的所有功能，迁移到 Python FastAPI 架构。

## 功能特性

### 多平台支持
| 日志类型 | 检测特征 | 分析模式 | AI 聊天 |
|---------|---------|---------|--------|
| 🪟 Windows | `.evtx` / `.dmp` / `tslog/` | 6 标签页结构化诊断 | Function Calling |
| 🐧 Linux | `var/log/` / `syslog` | 5 标签页结构化诊断 | Function Calling |
| 🔧 BMC/XCC | `ffdc.log` / `.tzz` 格式 | 文件浏览器 + AI 对话 | 上下文注入 (快速) |

### Windows 诊断
- **系统概览**: CPU/GPU/磁盘/NIC/SIO 硬件信息
- **系统诊断**: BugCheck 蓝屏事件、意外断电、LiveKernelEvent、硬件告警、安装崩溃关联
- **Dump 分析**: 支持 MDMP/PAGEDU64/PAGE/DUMP 四种格式，74 种 BugCheck 代码中文解释
- **SIOlog 分析**: Lenovo SIO/EC 控制器事件
- **整体总结**: 综合评分 + 行动建议

### Linux 诊断
- **系统概览**: OS 版本、CPU、内存、磁盘
- **内核诊断**: OOM killer、kernel panic/oops、硬件错误
- **系统日志**: 服务失败、认证失败、磁盘 I/O、网络错误
- **整体总结**: 严重性评估 + 发现汇总

### BMC/XCC 诊断 (NEW)
- 支持 `.tzz` 格式 (IBM/Lenovo XCC FFDC)
- 支持双层压缩自动解压 (`.tar.gz` 内含 `.tzz`)
- 文件浏览器 + AI 聊天双栏布局
- 上下文注入模式：自动加载所有日志文件，**秒级 AI 响应**
- BMC 关键日志智能排序 (`bmc-err.log` > `syshealth.log` > 普通 `.log`)

### AI 对话
- DeepSeek API 驱动
- Windows/Linux: Function Calling 模式（AI 可调工具深入分析）
- BMC/Other: 上下文注入模式（1.5MB 文件内容预加载，一轮出结果）
- BMC 关键文件优先级排序（借鉴 file-analyzer-web）

### 其他特性
- 拖拽上传 + 主机 SN 模态确认
- 文件树浏览器 + 文本/DMP 预览
- 历史记录管理（上传/下载/删除）
- 暗色主题 UI

## 环境要求

| 组件 | 说明 |
|------|------|
| Python | 3.10+ |
| Nginx | 反向代理 |
| 7-Zip | `.7z` 解压 |
| unrar | `.rar` 解压 |
| lzop | `.tzz` 解压 (IBM XCC FFDC) |

```bash
# Ubuntu/Debian
apt install nginx python3 python3-pip p7zip-full unrar lzop
pip install fastapi uvicorn aiofiles httpx python-evtx py7zr jinja2 python-multipart
```

## 部署

1. 克隆项目到 `/opt/log-analyzer/`
2. 配置 Nginx 反代（见下方）
3. 设置 DeepSeek API Key：

```python
# 编辑 main.py 中的环境变量
DEEPSEEK_API_KEY = "sk-your-key"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
```

4. 启动服务：

```bash
# 手动启动
python3 -m uvicorn main:app --host 127.0.0.1 --port 8002

# 或使用 systemd
sudo cp log-analyzer.service /etc/systemd/system/
sudo systemctl enable --now log-analyzer
```

### Nginx 配置

```nginx
location /log-analyzer/ {
    proxy_pass http://127.0.0.1:8002/;
    proxy_read_timeout 300s;
    proxy_connect_timeout 30s;
    proxy_send_timeout 60s;
    client_max_body_size 500M;
}
```

## 项目结构

```
/opt/log-analyzer/
├── main.py              # FastAPI 后端（全部逻辑）
├── templates/
│   ├── upload.html      # 上传页 + 历史记录
│   ├── analyze.html     # 分析页（三分支布局）
│   └── report.html      # 单报告页（遗留）
├── uploads/             # 上传文件 + 解压目录
└── reports/             # 缓存分析结果 + history.json
```

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/` | 上传首页 |
| GET | `/analyze/{job_id}` | 分析中心 |
| POST | `/api/upload` | 上传文件 (multipart + sn) |
| POST | `/api/analyze/{job_id}?analysis_type=X` | 触发分析 |
| GET | `/api/status/{job_id}` | 轮询进度 |
| GET | `/api/report/{job_id}?type=X` | 获取报告 |
| GET | `/api/files/{job_id}` | 文件树 |
| GET | `/api/file-content/{job_id}?path=P` | 文件内容/DMP 解析 |
| POST | `/api/chat/{job_id}` | AI 对话 |
| DELETE | `/api/job/{job_id}` | 删除任务 |
| GET | `/api/download/{job_id}` | 下载原包 |
| GET | `/api/history` | 历史列表 |

## 更新日志

### 2026-06-09 — 合并 file-analyzer-web 功能
- ✅ BMC/XCC 日志检测（`find_log_dir` 新增 `bmc`/`other` 返回类型）
- ✅ `.tzz` 格式解压支持
- ✅ 双层压缩自动解压（`.tar.gz` 内含 `.tzz`）
- ✅ BMC/Other 新布局：文件浏览器 + AI 聊天下半区
- ✅ AI 聊天分流：Windows/Linux → FC 模式，BMC/Other → 上下文注入模式
- ✅ 上下文注入：BMC 关键日志智能排序 + 1.5MB 上限
- ✅ DMP 内联解析支持（`/api/file-content/` 扩展）
- ✅ 首页系统类型徽章（🪟 Windows / 🐧 Linux / 🔧 BMC）

## License

Internal use.
