# 文件分析平台 - 变更记录

## 2026-06-08 重大更新

### 🚀 新功能

#### 1. 聊天记录持久化
- 新增 MySQL 表 `chat_history`，按文件 ID 存储完整对话历史
- 新增 `api/chat_history.php` — 支持保存/加载/清除聊天记录
- 前端 `analysis.js` 增加自动恢复和自动保存逻辑
- 对话头部新增 🗑️ 清除按钮，一键清空当前聊天记录

#### 2. HTML 文件直接渲染
- 新增 `api/serve.php` — 文件直出服务
- HTML 文件通过 iframe 嵌入渲染，不再显示源码
- 自动检测 GBK 编码并注入 `<meta charset>`，支持乱码 HTML 正确显示
- 支持图片（png/jpg/gif/webp）、PDF 等二进制文件直出

#### 3. 大文件流式加载
- 大文本文件（>5MB）不再直接拒绝，改为流式输出
- 前端 `analysis.js` 支持 iframe 嵌入加载大文件

#### 4. 新增 .tzz 格式解压
- 支持 IBM/Lenovo XCC FFDC 格式（`tar --lzop`）
- 新增依赖：`lzop` 工具（`apt-get install -y lzop`）

### ⚡ 性能优化

#### 文件列表缓存（`api/files.php`）
- **问题**：每次刷新遍历 6000+ 文件调用 `isReadableText()` → 2.4 秒
- **修复**：解压后生成 `_meta.json` 缓存，之后只读缓存 → **0.006 秒**（400 倍提升）

#### AI 对话上下文（`api/chat.php`）
- **问题1**：上下文上限仅 100KB（约 25K tokens），653 个可读文件只能加载 115 个（17%）
- **修复1**：上限提升至 **1.5MB**（约 375K tokens），充分利用 DeepSeek 1M 上下文
- **问题2**：文件排序优先 Windows `.evtx`（BMC 系统不存在），关键日志被截断
- **修复2**：改为 BMC 日志智能排序：
  - 优先级 0：`bmc-err.log`, `kernel-err.log`, `ffdc.log`, `component_activity.log` 等
  - 优先级 1：`syshealth.log`, `security.log`, `system.log` 等
  - 优先级 2：其他 `.log` 文件
  - 优先级 3：普通文本文件
- **结果**：653/653 文件全部加载，关键 BMC 日志 100% 覆盖

### 🛡️ 安全加固
- `api/helpers.php` 新增 `is_readable()` 前置检查
- `api/upload.php` 解压后自动 `chmod a+r` 修复文件权限

### 🐛 Bug 修复
- `.tzz` 格式上传后解压失败 → 已安装 `lzop` 依赖
- `analysis.html` 版本号更新至 v7（缓存刷新）

---

## 变更文件清单

### 新增
- `api/serve.php` — 文件直出服务
- `api/chat_history.php` — 聊天记录持久化 API

### 修改
- `api/chat.php` — AI 上下文扩大 15 倍 + BMC 日志优先排序
- `api/read.php` — HTML 渲染 + 大文件流式 + 错误信息优化
- `api/upload.php` — .tzz 格式支持 + 解压后权限修复
- `api/files.php` — _meta.json 缓存（性能 400 倍提升）
- `api/helpers.php` — is_readable 检查
- `js/analysis.js` — iframe 渲染 + 聊天记录持久化 + 版本 v7
- `css/style.css` — 清除按钮样式
- `analysis.html` — 版本号 v7 + 清除按钮
