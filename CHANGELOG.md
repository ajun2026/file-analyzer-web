## v3.8 — 2026-08-30（文件预览修复 + 布局优化 + HTML 渲染）

### 修复

- **file-content 500（asyncio 未导入）**：v3.5 的 Bug 11 修复用了 `asyncio.to_thread` 但 main.py 顶部未 `import asyncio` → 打开任何文件报 "name 'asyncio' is not defined" → 前端一直"加载中"
  - 修复：顶部补 `import asyncio`；实测 bios.rom 16MB 30ms 返回（512KB 限读 + 截断标记）
- **HTML/HTM 文件不可打开**：前端 readable 列表与服务端白名单均无 .html → Intel_Scope_Info.html 等打不开
  - 修复：两处白名单加 html/htm

### 新功能

- **HTML 文件渲染显示**：新增 `/api/file-raw/{job_id}`（HTML 全量返回 text/html）+ 前端 iframe 渲染（sandbox 隔离）
  - 点击 .html 文件 → 显示渲染页面（如 Intel System Scope Tool 的 Software/System/PCIe 选项卡）而非源码
- **文件 tab 替换模式**：右侧内容区作为左侧文件树的展示窗口——点击新文件替换当前文件 tab（始终最多 1 个——不累积）

### 布局优化（分析页）

- **左侧固定竖排**：「← 返回主界面 + ID + 📁 诊断文件」固定在左侧（不因文件 tab 变化移动）
- **tab 与返回同行**：系统/文件选项卡在右侧内容区顶部（与返回/ID 同一水平）
- **文件 tab 排最后**：文件选项卡在 AI/深度分析之后（系统 tab 顺序不变）
- **page-title 隐藏**：当前 tab 标题与 tab 栏重复——取消显示；ID 弱化（小灰字——保留售后定位用）

### 部署说明

- 拉取后重启服务生效；无数据库迁移
## v3.6 — 2026-08-30（Linux 分析精简 + varlog 兜底修复 + 界面同步 <公网入口IP>）

### 修复

- **varlog 兜底触发条件过严**：主路径从 dmesg 提取 kernel 后 os_info 非空 → 完整硬件提取不触发（纯 /var/log 包只剩内核信息）
  - 修复：无 OS 名称（os-release 缺失）即触发 `_extract_varlog_info()` 完整提取
  - 返回结构补 `varlog_fallback` 字段（前端显示"⚠️ 无 sosreport——信息从 /var/log 常规日志兜底提取"）
  - 实测：纯 var/log 包（dmesg/kern.log/syslog/dpkg.log/auth.log）→ Ubuntu 22.04 / Xeon 5418Y 96核 / 511GB / RTX A4000 / 主板 / BIOS / USB / Docker 全字段提取

### 同步（<公网入口IP> 部署实例——界面一致）

- **Linux 分析页选项卡精简**（6 → 3）：系统概览 / AI 分析 / 深度分析（内核诊断/系统日志/整体总结入口移除——渲染函数保留）
- **Linux 默认 tab**：linux_summary → linux_overview（进入即系统概览）
- **IDG 主界面**：纯色背景（去渐变）/ 全宽布局（去 max-width 居中——适配 iframe）/ 移除 h1 标题+logo+账号提示行（直接上传区）/ 上传区文字居中
- **分析页去边框**（零边框线分层）：sidebar/header 去掉 border（#161b22 纯色分层——方案 #5）

### 部署说明

- 拉取后重启服务生效；无数据库迁移
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
