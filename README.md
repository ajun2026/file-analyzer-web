# Log Analyzer — 日志诊断分析平台

统一的日志诊断分析系统，支持 **Windows 蓝屏**、**Linux 系统日志**、**BMC/XCC 服务器日志**。

> 原 PHP 版保留在 [`php-legacy`](../../tree/php-legacy) 分支。  
> 重构前快照：`v3.0-monolith` tag。

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
│   ├── upload.html             # 上传页 + 历史
│   ├── analyze.html            # 分析页 (三分支布局)
│   └── report.html             # 单报告页
└── requirements.txt
```

## 快速开始

```bash
# 安装
pip install -r requirements.txt
apt install p7zip-full unrar lzop

# 配置 DeepSeek API Key (编辑 chat/function_call.py)
DEEPSEEK_API_KEY = "sk-your-key"

# 运行
python3 main.py
# → http://127.0.0.1:8002
```

## 三类日志自动分流

| 类型 | 检测特征 | 分析布局 | AI 模式 |
|------|---------|---------|--------|
| 🪟 Windows | .evtx / .dmp / tslog/ | 6 标签页 | Function Calling |
| 🐧 Linux | var/log/ / syslog | 5 标签页 | Function Calling |
| 🔧 BMC | ffdc.log / .tzz | 文件浏览器 + AI | 上下文注入 |

## License

Internal use.
