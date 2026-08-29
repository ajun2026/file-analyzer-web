# Changelog — file-analyzer-web (Log Analyzer)

## v3.5 — 2026-08-28（Bug 修复 5 项 + 备用 AI 通道 + Linux var/log 增强）

### Bug 修复（合并上游后发现的）

- **GBK 文件名 4 漏网点**：深度提交 file_list / context_inject.py（4 处）/ 后台 context 写入——统一 `_clean_name()` 清洗（文件树 v3.4 已修）
- **file-content 全量读阻塞**：限读 512KB（截断标注）+ `asyncio.to_thread`（32MB 文件不再卡页面）
- **max_tokens 2000 不足 → 空回复**：function_call + 消费者 → 8000 + 空回复自动重试（reasoning 模型场景）
- **分析页默认 tab 不加载**：初始化激活默认 tab + 自动 runAnalysis
- **analyze.html `?.` ES2020（2 处）**：传统写法（老浏览器兼容）

### 新功能

- **② 备用 AI 通道（自动故障切换）**：
  - `.env` 双套配置（DEEPSEEK_API_KEY_2/BASE_URL_2/MODEL_2——同时非空才启用，MODEL_2 空回退主模型）
  - 主 → 备通道序 + 每通道最多 2 次重试；content 非空为唯一成功出口（reasoning 空回复视为失败）
  - 本次请求单向降级；下次从主开始（主恢复自动回归）；全部失败逐条错误报告
  - 接入：function_call（FC）/ context_inject（BMC）/ 消费者（深度分析）
- **③ Linux 系统概览 /var/log 兜底增强**：
  - `_extract_varlog_info()`：纯 var/log 包（无 sosreport）从 dmesg/kern.log/syslog/dpkg.log/auth.log 兜底提取
  - 字段：OS 版本（含 LTS 代号）/内核/主机名/CPU（型号/核数/BogoMIPS/频率）/内存/主板/BIOS/显卡（PCI ID→型号表，推断标注）/显卡驱动/硬盘/磁盘接口/网卡/USB/安全启动/架构/时区/桌面环境/Docker/主要用户
  - 触发：主路径 os_info 为空自动启用；前端三段式渲染（系统信息/硬件信息表格/软件信息）
  - 实测：SikunStation（Xeon Gold 5418Y 96 核 / 511GB / RTX A4000 / 4×16TB SATA）全字段提取 ✅

### 部署说明

- 拉取后重启服务生效
- 备用通道可选：.env 加 DEEPSEEK_API_KEY_2 / DEEPSEEK_BASE_URL_2 / DEEPSEEK_MODEL_2
- 无数据库迁移
