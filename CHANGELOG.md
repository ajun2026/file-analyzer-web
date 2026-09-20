## v3.11 — 2026-09-20（AI 逻辑对齐 + 端口可配 + 依赖补全）

> 来源：其它服务器部署 v3.10 时的反馈——包内混入"比现网旧"的文件，且 AI 逻辑只改了一半。

### 修复

- **AI 对话/总结路径未同步可靠性改造**：v3.10 只改了 `deep_analyze_consumer.py`（深度分析），
  而 `chat/function_call.py`（AI 对话 / 整体总结）仍是老逻辑——重试 2 次、超时 120s、无推理兜底。
  - 修复：`chat/function_call.py` 的 `_call_deepseek` 同步为 **重试 3 次（递增间隔 2s/4s）+ 超时 240s + `reasoning_content` 兜底**
  - 现在两条路径（对话 / 深度分析）口径一致

- **端口硬编码 8082**（`main.py`）：部署到使用其他端口（如 8002）的环境时需手工改代码，
  且易与同机服务冲突。
  - 修复：改为环境变量可配 —— `PORT=8002 python3 main.py`；未设置时默认 8082（兼容现有部署）
  - 同时 host 可配（`HOST` 环境变量）

- **`requirements.txt` 缺 `python-dotenv`**：`main.py` / `chat/function_call.py` 使用
  `from dotenv import load_dotenv`，但依赖清单未声明——缺包装机后报
  `legal header value b'Bearer'`（进程无 DEEPSEEK_API_KEY），AI 功能全部不可用。
  - 修复：requirements.txt 追加 `python-dotenv>=1.0.0`

### 部署提示

- 升级后重启服务，确认启动日志输出 `[main] starting on <host>:<port>`
- 自定义端口：`PORT=8002 python3 main.py`（无需改代码）
- 依赖安装：`pip install -r requirements.txt`（已含 python-dotenv）

## v3.10 — 2026-09-18（压缩格式兼容 + AI 调用可靠性 + 部署文档）

### 修复

- **`.rar` 解压失败（上传直接 500）**：服务器未安装 `unrar` 时，`detectors.py` 调用 `subprocess.run(['unrar', ...])` 抛 `FileNotFoundError`，上传页面报"服务器错误"或"日志目录不存在，请重新上传"
  - 修复：`.rar` 解压改为 **7z 优先 + unrar 兜底**（`p7zip-full` 几乎处处可用且支持 rar/rar5，避免依赖部分源未收录的 `unrar`）
  - 同时安装 `unrar`（`unrar-free` 兜底）以提升分卷/旧版加密场景兼容性

- **解压异常返回 500 HTML**（前端显示 `Unexpected token 'I', "Internal S"...`）：上传接口的解压步骤无异常捕获，异常直接冒泡为 500
  - 修复：`main.py` 解压步骤加 try/except，返回结构化 JSON —— `{"error": "解压失败：<类型>: <原因>", "hint": "支持的格式：zip / 7z / rar / tar.gz / tar.xz / tzz"}`（HTTP 400）

- **AI 分析误报"空回复"**：推理模型（deepseek-v4-flash 等）先输出 `reasoning_content`（思考）再输出 `content`（正文），两者共享 `max_tokens`；当正文为空时原逻辑直接判定"空回复"，导致 `AI 分析所有通道均失败: ... 空回复(第N次)`
  - 修复：`content` 为空时兜底取 `reasoning_content`（附注"以上为模型思考内容"），避免白跑一轮消耗

### 优化

- **AI 调用重试策略**：每通道 2 次 → **3 次**，并加入递增重试间隔（2s / 4s），应对网关抖动与限流
- **AI 调用超时**：180s → **240s**（长日志上下文 + 推理模型响应较慢，原超时过短会误判失败）

### 文档

- **README 补充部署必查项**：压缩工具（7z / unrar / lzop）缺失后果对照表、逐项自查命令（`which 7z unrar lzop`、`7z i | grep -i rar`）、`.rar` 双保险策略说明、解压失败错误提示解读
- **README 补充 AI 调用可靠性章节**：多通道配置（主/备）、重试与超时策略、推理模型兜底机制、常见现象排查表

## v3.9 — 2026-09-11（DMP 解析线程化 + AI key 修复 + 默认视图优化）

### 修复

- **DMP 解析 to_thread**：`/api/file-content` 的 .dmp 分支 + `/api/dump-detail` 两处 `parse_single_dump()` 同步调用改为 `asyncio.to_thread`——async 接口内文件 IO 不再阻塞事件循环（打开大 DMP 不拖慢其他请求）
- **AI 分析 Bearer 空 key**：main.py 不加载 .env → 进程无 DEEPSEEK_API_KEY → AI 分析报 `legal header value b'Bearer`，AI 总结卡 `analyzing_summary`（progress 10）永不完成。修复：main.py 顶部 `load_dotenv()` + venv 补装 python-dotenv

### 优化

- **分析页默认视图**：打开 job 默认「📄 系统概览」（本地生成、秒开）；「📊 整体总结」等 AI 分析**不自动触发**（点击 tab 才跑）——避免一打开页面就转圈等 AI
- 主题变量收敛：IDG 硬编码颜色 → CSS 变量（为后续主题能力打基础）

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
