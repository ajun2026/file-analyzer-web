"""Function Calling chat for Windows/Linux."""
import json, httpx, asyncio
from pathlib import Path
from typing import Optional
from fastapi.responses import JSONResponse
from detectors import detect_encoding, iter_evtx_cached
from analyzers.dump_parser import parse_single_dump

DEEPSEEK_API_KEY = "sk-96ebbb3ccd854d41b86e6599b56e8e28"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"

# In-memory chat history per job
chat_sessions: dict = {}  # job_id -> list of {"role":"user"|"assistant"|"tool", "content":"..."}

CHAT_SYSTEM_PROMPT = """你是 IDG 日志诊断专家助手，正在帮助用户分析一份诊断日志包（支持 Windows 和 Linux 系统）。

你可以使用以下工具：
- list_files: 列出日志目录中的所有诊断文件
- read_text_file: 读取 .txt/.log 等文本文件内容（自动检测 GBK/UTF-8 编码）
- read_evtx_events: 查询 .evtx 事件日志中指定 Event ID 的记录（仅 Windows 日志有效）
- read_dump_file: 解析指定的 .dmp 蓝屏转储文件，提取 BugCheck 代码、参数和驱动列表（包括第三方驱动）
- read_report: 读取已完成的诊断分析报告

工具使用原则（重要！）：
- 用户提到"dump"、"蓝屏"、"驱动"、"崩溃"时，先调用 list_files 看有哪些 .dmp，然后调用 read_dump_file 解析
- 一次只解析 1-2 个 dump 文件即可，不需要逐个解析所有 dump
- 如果 read_dump_file 返回"【重要】其他 dump 文件也是同样类型"，应立即停用 read_dump_file，改用 read_evtx_events
- 不要直接拒绝用户，应先用工具获取数据再给结论

分析维度：
- Windows 日志：evtx 事件日志、系统信息文本、Dump 文件、SIOlog
- Linux 日志：syslog/kern.log/messages/dmesg/auth.log 等系统日志文件

Linux 诊断重点：
- OOM killer 触发记录、kernel panic / oops
- 服务崩溃 (systemd service failed)
- 硬件/磁盘 I/O 错误
- 认证失败（暴力破解检测）

Windows 诊断重点：
- BugCheck 蓝屏代码及参数
- 意外断电 Event 41 / 6008
- 硬件告警 Event 12/13
- LiveKernelEvent / 驱动崩溃
- dump 文件中的第三方驱动列表（非微软签名驱动是排查重点）

回复要求：
- 用中文回答
- 遇到诊断问题必须先调用工具，不要凭空猜测
- 回答简洁专业，给出可操作的诊断建议
- 引用具体的事件 ID、时间戳、数值"""

CHAT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": "列出 tslog 诊断目录中的所有文件（.txt/.log/.evtx/.dmp等）",
            "parameters": {"type": "object", "properties": {}, "required": []}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_text_file",
            "description": "读取 tslog 目录中指定的文本诊断文件（.txt/.log等），自动处理 GBK/UTF-8 编码",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "文件名，如 Systeminfo.txt, SMARTINFO.txt, dxdiag.txt, SIO_Events.log"}
                },
                "required": ["filename"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_evtx_events",
            "description": "查询指定 .evtx 事件日志中指定 Event ID 的记录。注意：只搜索 System.evtx 和 Application.evtx",
            "parameters": {
                "type": "object",
                "properties": {
                    "evtx_name": {"type": "string", "description": "evtx文件名，如 System.evtx 或 Application.evtx"},
                    "event_id": {"type": "integer", "description": "要查询的 Event ID，如 41, 1001, 6008 等。设 0 表示返回所有错误级别的事件"}
                },
                "required": ["evtx_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_report",
            "description": "读取已缓存的诊断分析报告（需先运行对应分析）",
            "parameters": {
                "type": "object",
                "properties": {
                    "report_type": {"type": "string", "enum": ["overview", "diagnostics", "dump", "siolog", "summary"],
                                    "description": "报告类型: overview=系统概览, diagnostics=系统诊断, dump=Dump分析, siolog=SIOlog, summary=整体总结"}
                },
                "required": ["report_type"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_dump_file",
            "description": "解析指定的 .dmp 蓝屏转储文件，提取 BugCheck 代码、参数、驱动列表。可以指定文件名或路径（如 osdump/053126-7937-01.dmp）",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "dmp 文件路径或文件名，如 osdump/053126-7937-01.dmp"}
                },
                "required": ["filename"]
            }
        }
    },
]


def _get_tslog(job_id: str) -> Optional[Path]:
    """Get tslog path for a job"""
    if job_id not in jobs or not jobs[job_id].get("tslog_path"):
        return None
    p = Path(jobs[job_id]["tslog_path"])
    return p if p.exists() else None


def _execute_tool(job_id: str, tool_name: str, arguments: dict) -> str:
    """Execute a tool call and return the result as a string"""
    tslog = _get_tslog(job_id)
    if not tslog:
        return "错误：日志目录不存在，请重新上传文件"

    try:
        if tool_name == "list_files":
            files = []
            for f in sorted(tslog.rglob("*")):
                if f.is_file():
                    rel = f.relative_to(tslog)
                    size_kb = round(f.stat().st_size / 1024, 1)
                    files.append(f"  {rel} ({size_kb} KB)")
            return "tslog 目录文件列表：\n" + "\n".join(files[:80]) if files else "目录为空"

        elif tool_name == "read_text_file":
            filename = arguments.get("filename", "")
            fp = tslog / filename
            if not fp.exists():
                # Try searching
                for alt in tslog.rglob(filename):
                    fp = alt
                    break
            if not fp.exists():
                return f"文件 {filename} 未找到。可用 list_files 查看文件列表"
            if fp.stat().st_size > 200 * 1024:
                return f"文件 {filename} 过大（{round(fp.stat().st_size/1024)}KB），只显示前 200KB：\n" + \
                       _read_text_safe(fp)[:200000]
            return _read_text_safe(fp)

        elif tool_name == "read_evtx_events":
            evtx_name = arguments.get("evtx_name", "System.evtx")
            event_id = arguments.get("event_id", 0)
            evtx_path = tslog / "oslog" / evtx_name
            if not evtx_path.exists():
                return f"{evtx_name} 未找到。可用的 evtx 文件请用 list_files 查看 oslog/ 子目录"

            results = []
            count = 0
            for eid, lvl, ts, prov, root in iter_evtx_cached(evtx_path, max_events=500):
                if event_id and eid != event_id:
                    continue
                if not event_id and lvl > 3:
                    continue  # Skip info/debug when querying all errors
                count += 1
                if count > 50:
                    break
                line = f"Event {eid} | {ts} | Level {lvl} | Provider: {prov}"
                if root is not None:
                    data_items = root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data')
                    for d in data_items[:3]:
                        if d.text and d.text.strip():
                            line += f"\n  {d.get('Name','')}: {d.text.strip()[:120]}"
                results.append(line)

            if not results:
                return f"{evtx_name} 中未找到 Event {event_id} 的记录" if event_id else \
                       f"{evtx_name} 中未找到错误/警告级别记录"
            return f"{evtx_name} 中{'Event ' + str(event_id) if event_id else '错误/警告'}记录（最多50条）：\n" + "\n---\n".join(results)

        elif tool_name == "read_report":
            report_type = arguments.get("report_type", "")
            report_path = REPORT_DIR / f"{job_id}_{report_type}.json"
            if not report_path.exists():
                return f"{report_type} 报告尚未生成，请先在诊断页面点击对应分析标签"
            import json as _json
            with open(report_path, 'r', encoding='utf-8') as f:
                data = _json.load(f)
            # Return a structured summary
            result = f"=== {data.get('title', report_type)} ===\n"
            if 'summary' in data:
                result += f"摘要: {data['summary']}\n"
            if 'severity' in data:
                result += f"严重级别: {data['severity']}\n"
            if 'findings' in data:
                result += "发现:\n"
                for f_item in data['findings']:
                    result += f"  - {f_item}\n"
            if 'bugcheck_count' in data:
                result += f"蓝屏次数: {data['bugcheck_count']}\n"
            if 'unexpected_shutdowns_count' in data:
                result += f"意外断电: {data['unexpected_shutdowns_count']}\n"
            if 'hardware_error_count' in data:
                result += f"硬件告警: {data['hardware_error_count']}\n"
            if 'lke_count' in data:
                result += f"LiveKernelEvent: {data['lke_count']}\n"
            if 'total_dumps' in data:
                result += f"Dump文件数: {data['total_dumps']}\n"
            if 'system' in data:
                sys_info = data['system']
                if sys_info.get('hostname'):
                    result += f"主机名: {sys_info['hostname']}\n"
                if sys_info.get('cpu'):
                    result += f"CPU: {sys_info['cpu']}\n"
                if sys_info.get('os_name'):
                    result += f"OS: {sys_info['os_name']} {sys_info.get('os_version','')}\n"
            if 'gpu' in data:
                gpu = data['gpu']
                if gpu.get('name'):
                    result += f"显卡: {gpu['name']}\n"
            if 'disks' in data:
                result += f"磁盘: {len(data['disks'])} 个\n"
                for d in data['disks'][:3]:
                    result += f"  - {d.get('model', '?')} | {d.get('capacity', '?')}\n"
            if len(result) > 2000:
                result = result[:2000] + "\n...(内容被截断，完整报告请在诊断页面查看)"
            return result

        elif tool_name == "read_dump_file":
            filename = arguments.get("filename", "")
            fp = tslog / filename
            if not fp.exists():
                # Try searching in osdump/
                for alt in tslog.rglob(filename):
                    fp = alt
                    break
            if not fp.exists():
                return f"文件 {filename} 未找到。可用的 dmp 文件请用 list_files 查看 osdump/ 子目录"
            if not fp.suffix.lower() == '.dmp':
                return f"{filename} 不是 .dmp 文件"
            info = parse_single_dump(fp, tslog)

            lines = [f"=== {info['filename']} ==="]
            lines.append(f"大小: {info['size_kb']} KB ({info['size_mb']} MB)")
            lines.append(f"类型: {info.get('dump_type', '未知')}")
            
            if info.get('error'):
                lines.append(f"⚠️ {info['error']}")
                return "\n".join(lines)
            
            if info.get('bugcheck'):
                bc = info['bugcheck']
                lines.append(f"\nBugCheck: {bc['code']} — {bc['name']}")
                lines.append(f"说明: {bc['description']}")
            elif info.get('bugcheck_raw'):
                lines.append(f"\nBugCheck 原始值: {info['bugcheck_raw']}")
            
            if info.get('bugcheck_params'):
                lines.append(f"参数: {', '.join(info['bugcheck_params'])}")
            
            if info.get('drivers'):
                lines.append(f"\n加载的驱动 ({info['driver_count']}个):")
                for d in info['drivers']:
                    lines.append(f"  • {d}")
            
            if info.get('third_party_drivers'):
                lines.append(f"\n🔍 第三方驱动 ({info['third_party_count']}个) — 排查重点:")
                for d in info['third_party_drivers']:
                    lines.append(f"  ⚠ {d}")

            if info.get('driver_note'):
                lines.append(f"\n{info['driver_note']}")

            if info.get('event_1001'):
                lines.append(f"\n📋 关联的系统事件 (Event 1001 BugCheck):")
                for i, evt in enumerate(info['event_1001'][:3], 1):
                    lines.append(f"  [{i}] {evt.get('time', '?')}")
                    for k, v in evt.items():
                        if k != 'time' and v:
                            lines.append(f"      {k}: {v[:150]}")

            return "\n".join(lines)

        else:
            return f"未知工具: {tool_name}"

    except Exception as e:
        return f"工具执行错误: {str(e)[:200]}"
def _read_text_safe(filepath: Path) -> str:
    """Read text file with auto encoding detection"""
    enc = detect_encoding(filepath)
    try:
        with open(filepath, 'r', encoding=enc, errors='replace') as f:
            return f.read()
    except Exception:
        return f"（无法读取文件 {filepath.name}）"


async def _call_deepseek(messages: list) -> dict:
    """Call DeepSeek API with httpx, return the response message"""
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(
            f"{DEEPSEEK_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "deepseek-chat",
                "messages": messages,
                "tools": CHAT_TOOLS,
                "tool_choice": "auto",
                "temperature": 0.3,
                "max_tokens": 2000,
            },
        )
        resp.raise_for_status()
        return resp.json()
async def _chat_function_calling(job_id: str, user_message: str, tslog):
    """Function Calling mode for Windows/Linux logs"""

    # Get or create chat session
    if job_id not in chat_sessions:
        chat_sessions[job_id] = [
            {"role": "system", "content": CHAT_SYSTEM_PROMPT}
        ]

    # Add user message
    chat_sessions[job_id].append({"role": "user", "content": user_message})

    # Keep history manageable — but NEVER cut between tool_calls and tool messages
    if len(chat_sessions[job_id]) > 22:
        # Start with system prompt + last 20 messages
        trimmed = chat_sessions[job_id][:1] + chat_sessions[job_id][-20:]
        # Walk forward to find a safe start: skip orphaned tool messages
        safe_start = 1  # right after system prompt
        while safe_start < len(trimmed):
            msg = trimmed[safe_start]
            if msg["role"] == "tool":
                # This tool message has no preceding assistant(tool_calls) — skip it
                safe_start += 1
            else:
                break
        chat_sessions[job_id] = trimmed[:1] + trimmed[safe_start:]

    try:
        # Work on a COPY to avoid corrupting chat_sessions on error
        messages = chat_sessions[job_id].copy()

        # Main conversation loop (max 10 tool-call rounds)
        for _ in range(10):
            result = await _call_deepseek(messages)
            choice = result["choices"][0]
            msg = choice["message"]

            # Check for tool calls
            if msg.get("tool_calls"):
                # Normalize tool_calls format for DeepSeek compatibility
                normalized_tcs = []
                for tc in msg["tool_calls"]:
                    normalized_tcs.append({
                        "id": tc["id"],
                        "type": "function",
                        "function": tc["function"]
                    })

                # Add assistant message with tool_calls (no content key when tool_calls present)
                asst_msg = {"role": "assistant", "tool_calls": normalized_tcs}
                if msg.get("content"):
                    asst_msg["content"] = msg["content"]
                messages.append(asst_msg)

                # Execute each tool in thread pool to avoid blocking event loop
                for tc in msg["tool_calls"]:
                    func = tc["function"]
                    args = json.loads(func["arguments"]) if isinstance(func["arguments"], str) else func["arguments"]
                    tool_result = await asyncio.to_thread(_execute_tool, job_id, func["name"], args)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": tool_result,
                    })

                # Continue loop to get next response
                continue

            # No tool calls → final answer
            reply = msg.get("content", "")
            messages.append({"role": "assistant", "content": reply})

            # Only on success, update the real session
            chat_sessions[job_id] = messages

            return JSONResponse({"reply": reply})

        # Too many tool call rounds — give partial summary
        return JSONResponse({"reply": "分析轮次已达上限。请尝试更具体的问题，例如：\n• 「解析 osdump/053126-7937-01.dmp」指定单个 dump\n• 「查 System.evtx 的 Event 1001」查询事件日志\n• 「先运行 Dump 分析」生成完整报告后再问我"})

    except httpx.HTTPStatusError as e:
        return JSONResponse({"error": f"API 调用失败: {e.response.status_code} - {e.response.text[:200]}"},
                           status_code=502)
    except Exception as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=500)
