#!/usr/bin/env python3
"""Log Analyzer — FastAPI entry point."""
import json, os, uuid, threading, subprocess, shutil, re
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import FastAPI, File, Form, UploadFile, Request
from fastapi.responses import HTMLResponse, JSONResponse
import jinja2, aiofiles, httpx

from detectors import (load_history, save_history, add_to_history,
    detect_encoding, extract_archive, find_log_dir, normalize_log_structure,
    find_tslog_dir, iter_evtx, MAX_EVENTS, UPLOAD_DIR, REPORT_DIR, BASE_DIR)
from analyzers.windows import (analyze_overview, analyze_system_diagnostics,
    analyze_dump, analyze_siolog, analyze_summary)
from analyzers.linux import (analyze_linux_overview, analyze_linux_kernel,
    analyze_linux_syslog, analyze_linux_summary)
from analyzers.dump_parser import (parse_single_dump, BUGCHECK_MAP, get_bugcheck_info)
from chat.function_call import (_chat_function_calling, _call_deepseek,
    _execute_tool, _get_tslog, CHAT_SYSTEM_PROMPT, CHAT_TOOLS,
    DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL)
from chat.context_inject import _chat_context_inject

app = FastAPI(title="Log Analyzer")
CHINA_TZ = timezone(timedelta(hours=8))
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(BASE_DIR / "templates"), autoescape=True)
jobs = {}
chat_sessions = {}

# Inject globals into submodules that reference them
import chat.function_call as _fc
_fc.jobs = jobs
_fc.chat_sessions = chat_sessions

ANALYZERS = {
    "overview": analyze_overview,
    "diagnostics": analyze_system_diagnostics,
    "dump": analyze_dump,
    "siolog": analyze_siolog,
    "summary": analyze_summary,
    # Linux analyzers
    "linux_overview": analyze_linux_overview,
    "linux_kernel": analyze_linux_kernel,
    "linux_syslog": analyze_linux_syslog,
    "linux_summary": analyze_linux_summary,
}

# Map of standard analysis types for summary
_STANDARD_TYPES = ["overview", "diagnostics", "dump", "siolog"]
_LINUX_TYPES = ["linux_overview", "linux_kernel", "linux_syslog"]


# ─── Background Analysis ─────────────────────────────────────
def run_analysis_bg(job_id: str, analysis_type: str):
    """Run a specific analysis in background thread."""
    try:
        j = jobs[job_id]
        tslog_path = j.get("tslog_path")
        if not tslog_path or not Path(tslog_path).exists():
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = "日志目录不存在，请重新上传"
            return

        tslog = Path(tslog_path)
        jobs[job_id]["status"] = f"analyzing_{analysis_type}"
        jobs[job_id]["progress"] = 10

        analyzer = ANALYZERS.get(analysis_type)
        if not analyzer:
            jobs[job_id]["status"] = "error"
            jobs[job_id]["error"] = f"未知分析类型: {analysis_type}"
            return

        result = analyzer(tslog)
        jobs[job_id]["progress"] = 90

        # Save to file
        report_path = REPORT_DIR / f"{job_id}_{analysis_type}.json"
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2, default=str)

        jobs[job_id]["progress"] = 100
        jobs[job_id]["status"] = "done"
        jobs[job_id][f"report_{analysis_type}"] = str(report_path)

    except Exception as e:
        jobs[job_id]["status"] = "error"
        jobs[job_id]["error"] = str(e)


# ─── Restore jobs from history on startup ──────────────────
for h in load_history():
    jid = h["job_id"]
    os_type = h.get("os_type", "windows")
    tslog_path = None
    ext_dir = None
    # Find the extract directory for this job
    for d in UPLOAD_DIR.glob(f"extract_*{jid}*"):
        ext_dir = d
        break
    if ext_dir and ext_dir.exists():
        tslog, _ = find_log_dir(ext_dir)
        tslog_path = str(tslog) if tslog else str(ext_dir)
    if not tslog_path:
        continue  # skip if no extract dir found
    jobs[jid] = {
        "status": "ready", "progress": 0,
        "filename": h["filename"], "size": int(h["size_mb"] * 1048576),
        "tslog_path": tslog_path, "evtx_count": h["evtx_count"],
        "os_type": os_type,
        "created_at": h["created_at"],
    }


# ─── Routes ───────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    history = load_history()
    return jinja_env.get_template("upload.html").render(history_json=json.dumps(history, ensure_ascii=False))


@app.get("/report/{job_id}", response_class=HTMLResponse)
async def view_report(job_id: str):
    return jinja_env.get_template("report.html").render(job_id=job_id)


@app.get("/analyze/{job_id}", response_class=HTMLResponse)
async def analyze_page(job_id: str):
    """New unified analysis page with file tree + tabs"""
    os_type = "windows"
    if job_id not in jobs:
        # Try to load from history
        history = load_history()
        for h in history:
            if h["job_id"] == job_id:
                os_type = h.get("os_type", "windows")
                return jinja_env.get_template("analyze.html").render(
                    job_id=job_id, os_type=os_type,
                    history_entry=json.dumps(h, ensure_ascii=False))
        return HTMLResponse("<h1>任务不存在</h1><p>该日志可能已被清理，请重新上传</p>", status_code=404)
    os_type = jobs[job_id].get("os_type", "windows")
    return jinja_env.get_template("analyze.html").render(job_id=job_id, os_type=os_type, history_entry="{}")


@app.get("/api/history")
async def get_history():
    return JSONResponse(load_history())


@app.get("/api/files/{job_id}")
async def list_files(job_id: str):
    """List all files in the extracted tslog directory"""
    if job_id not in jobs or not jobs[job_id].get("tslog_path"):
        return JSONResponse({"error": "任务不存在"}, status_code=404)

    tslog = Path(jobs[job_id]["tslog_path"])
    if not tslog.exists():
        return JSONResponse({"error": "日志目录不存在"}, status_code=404)

    def build_tree(path: Path, prefix: str = "") -> list:
        items = []
        try:
            entries = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))
        except (PermissionError, FileNotFoundError, OSError):
            return items
        for entry in entries:
            try:
                is_dir = entry.is_dir()
                is_file = entry.is_file()
                is_sym = entry.is_symlink()
            except OSError:
                # Broken symlink or inaccessible — treat as plain file
                is_dir, is_file, is_sym = False, False, True
            item = {
                "name": entry.name,
                "type": "dir" if is_dir else "file",
                "path": str(entry.relative_to(tslog)),
            }
            if is_file or is_sym:
                try:
                    item["size"] = entry.stat().st_size
                except OSError:
                    item["size"] = 0
                # Detect file type category
                ext = entry.suffix.lower()
                if ext == '.evtx':
                    item["category"] = "events"
                elif ext == '.dmp':
                    item["category"] = "dump"
                elif entry.name in ('Systeminfo.txt', 'dxdiag.txt', 'Tasklist.txt', 'SMARTINFO.txt', 'NVIDIA_INFO.txt'):
                    item["category"] = "hardware"
                elif 'sio' in entry.name.lower():
                    item["category"] = "siolog"
                elif ext in ('.txt', '.log'):
                    item["category"] = "text"
            else:
                item["children"] = build_tree(entry, prefix)
            items.append(item)
        return items

    tree = build_tree(tslog)
    try:
        total_files = sum(1 for _ in tslog.rglob('*') if _.is_file() or _.is_symlink())
    except OSError:
        total_files = 0

    return JSONResponse({
        "job_id": job_id,
        "tslog_name": tslog.name,
        "total_files": total_files,
        "tree": tree,
    })


@app.get("/api/file-content/{job_id}")
async def get_file_content(job_id: str, path: str = ""):
    """Read a text file from the tslog directory"""
    if job_id not in jobs or not jobs[job_id].get("tslog_path"):
        return JSONResponse({"error": "任务不存在"}, status_code=404)

    tslog = Path(jobs[job_id]["tslog_path"])
    filepath = (tslog / path).resolve()

    # Security: ensure file is within tslog directory
    if not str(filepath).startswith(str(tslog.resolve())):
        return JSONResponse({"error": "非法路径"}, status_code=403)

    if not filepath.exists() or not filepath.is_file():
        return JSONResponse({"error": "文件不存在"}, status_code=404)

    # Only allow readable text files + dmp (also allow extension-less files)
    ext = filepath.suffix.lower()
    if ext and ext not in ('.txt', '.log', '.rom', '.csv', '.xml', '.ini', '.cfg', '.inf', '.evt', '.dmp'):
        return JSONResponse({"error": f"不支持预览 .{ext} 文件"}, status_code=400)

    size = filepath.stat().st_size
    # DMP files get parsed via the parser (handles large files by reading headers)
    if ext == '.dmp':
        if size == 0:
            return JSONResponse({"error": "DMP 文件为空"}, status_code=400)
        info = parse_single_dump(filepath, tslog)
        text_lines = [f"=== {info['filename']} ===",
                      f"大小: {info['size_kb']} KB ({info['size_mb']} MB)",
                      f"类型: {info.get('dump_type', '未知')}"]
        if info.get('error'):
            text_lines.append(f"⚠️ {info['error']}")
        if info.get('bugcheck'):
            bc = info['bugcheck']
            text_lines.append(f"\nBugCheck: {bc['code']} — {bc['name']}")
            text_lines.append(f"说明: {bc['description']}")
        elif info.get('bugcheck_raw'):
            text_lines.append(f"\nBugCheck 原始值: {info['bugcheck_raw']}")
        if info.get('bugcheck_params'):
            text_lines.append(f"参数: {', '.join(info['bugcheck_params'])}")
        if info.get('drivers'):
            text_lines.append(f"\n加载的驱动 ({info['driver_count']}个):")
            for d in info['drivers']:
                text_lines.append(f"  • {d}")
        if info.get('third_party_drivers'):
            text_lines.append(f"\n🔍 第三方驱动 ({info['third_party_count']}个):")
            for d in info['third_party_drivers']:
                text_lines.append(f"  ⚠ {d}")
        if info.get('driver_note'):
            text_lines.append(f"\n{info['driver_note']}")
        if info.get('event_1001'):
            text_lines.append(f"\n📋 关联系统事件 (Event 1001):")
            for i, evt in enumerate(info['event_1001'][:3], 1):
                text_lines.append(f"  [{i}] {evt.get('time', '?')}")
        return JSONResponse({"content": "\n".join(text_lines), "size": size})

    enc = detect_encoding(filepath)
    try:
        with open(filepath, 'r', encoding=enc, errors='replace') as f:
            content = f.read()
    except Exception as e:
        return JSONResponse({"error": f"读取失败: {e}"}, status_code=500)

    return JSONResponse({
        "filename": filepath.name,
        "path": path,
        "size": size,
        "encoding": enc,
        "content": content,
    })


@app.get("/api/dump-detail/{job_id}")
async def get_dump_detail(job_id: str, file: str = ""):
    """Get detailed analysis for a single .dmp file"""
    if job_id not in jobs or not jobs[job_id].get("tslog_path"):
        return JSONResponse({"error": "任务不存在"}, status_code=404)
    tslog = Path(jobs[job_id]["tslog_path"])
    filepath = (tslog / file).resolve()
    if not str(filepath).startswith(str(tslog.resolve())):
        return JSONResponse({"error": "非法路径"}, status_code=403)
    if not filepath.exists() or filepath.suffix.lower() != '.dmp':
        return JSONResponse({"error": "不是有效的 .dmp 文件"}, status_code=400)
    result = parse_single_dump(filepath)
    return JSONResponse(result)


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...), sn: str = Form("")):
    """上传日志包，仅保存+解压，不分析。支持 Windows (.7z/.zip/.rar) 和 Linux (.tar.gz/.tgz/.tar)"""
    job_id = uuid.uuid4().hex[:12]
    filename = file.filename.lower()
    file_stem = Path(file.filename).suffix.lower()

    # Accept .tar.gz, .tgz, .tzz, .tar.xz as well as standard archives
    is_tar = any(filename.endswith(ext) for ext in ['.tar.gz', '.tgz', '.tar', '.tzz', '.tar.xz'])
    if not is_tar and file_stem not in ('.7z', '.zip', '.rar'):
        return JSONResponse(
            {"error": f"不支持的文件格式，请上传 .7z / .zip / .rar (Windows) 或 .tar.gz / .tgz / .tar / .tar.xz / .tzz (Linux/BMC)"},
            status_code=400)

    # Determine extension for filename
    if filename.endswith('.tar.gz'):
        save_ext = '.tar.gz'
    elif filename.endswith('.tgz'):
        save_ext = '.tgz'
    elif filename.endswith('.tzz'):
        save_ext = '.tzz'
    elif filename.endswith('.tar.xz'):
        save_ext = '.tar.xz'
    else:
        save_ext = file_stem

    filepath = UPLOAD_DIR / f"{job_id}{save_ext}"
    async with aiofiles.open(filepath, 'wb') as f:
        while chunk := await file.read(1024 * 1024):
            await f.write(chunk)

    # Extract
    extract_dir = extract_archive(filepath)
    tslog, os_type = find_log_dir(extract_dir)
    
    # Auto handle double-compressed archives (e.g. .tar.gz containing .tzz)
    if os_type == "unknown" and not tslog:
        inner_tzz = list(extract_dir.glob("*.tzz"))
        if inner_tzz:
            inner_path = inner_tzz[0]
            inner_extract = extract_dir / "extracted"
            inner_extract.mkdir(exist_ok=True)
            subprocess.run(['tar', '--lzop', '-xf', str(inner_path), '-C', str(inner_extract)],
                           capture_output=True, timeout=300)
            tslog2, os_type2 = find_log_dir(inner_extract)
            if tslog2:
                tslog, os_type = tslog2, os_type2
    
    tslog_path = str(tslog) if tslog else None
    
    # Normalize non-standard Windows log structures (create oslog/osdump)
    if tslog and os_type == "windows":
        normalize_log_structure(tslog)

    # Count files for preview
    evtx_count = 0
    if tslog:
        if os_type == "windows":
            evtx_count = len(list(tslog.rglob("*.evtx")))
        elif os_type in ("linux", "bmc", "other"):
            # Count total files for Linux/BMC/other
            evtx_count = sum(1 for _ in tslog.rglob("*") if _.is_file())

    jobs[job_id] = {
        "status": "ready",
        "progress": 0,
        "filename": file.filename,
        "size": filepath.stat().st_size,
        "tslog_path": tslog_path,
        "evtx_count": evtx_count,
        "os_type": os_type,
        "sn": sn,
        "created_at": datetime.now(CHINA_TZ).isoformat(),
    }

    # Save to persistent history
    add_to_history(job_id, file.filename,
                   round(filepath.stat().st_size / 1048576, 1),
                   evtx_count, tslog_path, os_type, sn)

    # Build friendly message based on OS type
    if os_type == "windows":
        friendly_msg = "Windows 日志已上传，请选择分析类型"
    elif os_type == "linux":
        friendly_msg = "Linux 日志已上传，请选择分析类型"
    elif os_type == "bmc":
        friendly_msg = "BMC/XCC 日志已上传，可使用 AI 对话分析"
    else:
        friendly_msg = "日志已上传，可使用 AI 对话分析"

    return JSONResponse({
        "job_id": job_id,
        "status": "ready",
        "filename": file.filename,
        "size_mb": round(filepath.stat().st_size / 1048576, 1),
        "evtx_count": evtx_count,
        "os_type": os_type,
        "sn": sn,
        "message": friendly_msg,
    })


@app.post("/api/analyze/{job_id}")
async def trigger_analysis(job_id: str, analysis_type: str = "overview"):
    """触发指定类型的分析"""
    if job_id not in jobs:
        return JSONResponse({"error": "任务不存在，请先上传文件"}, status_code=404)

    if analysis_type not in ANALYZERS:
        return JSONResponse({"error": f"未知分析类型: {analysis_type}，可选: {list(ANALYZERS.keys())}"}, status_code=400)

    jobs[job_id]["status"] = f"analyzing_{analysis_type}"
    jobs[job_id]["progress"] = 5

    thread = threading.Thread(
        target=run_analysis_bg, args=(job_id, analysis_type), daemon=True)
    thread.start()

    return JSONResponse({
        "job_id": job_id,
        "analysis_type": analysis_type,
        "status": "started",
    })


@app.get("/api/status/{job_id}")
async def job_status(job_id: str):
    if job_id not in jobs:
        return JSONResponse({"error": "Job not found"}, status_code=404)
    j = jobs[job_id]
    return JSONResponse({
        "job_id": job_id,
        "status": j.get("status"),
        "progress": j.get("progress", 0),
        "error": j.get("error"),
    })


@app.get("/api/report/{job_id}")
async def get_report(job_id: str, type: str = "overview"):
    report_path = REPORT_DIR / f"{job_id}_{type}.json"
    if not report_path.exists():
        return JSONResponse({"error": f"报告未找到或分析未完成 (type={type})"}, status_code=404)
    with open(report_path, 'r', encoding='utf-8') as f:
        return JSONResponse(json.load(f))


@app.delete("/api/job/{job_id}")
async def delete_job(job_id: str):
    """删除一个上传任务及其所有关联文件"""
    import shutil

    # Remove from in-memory
    job = jobs.pop(job_id, None)

    # Remove extracted directory and archive
    if job and job.get("tslog_path"):
        tslog = Path(job["tslog_path"])
        # The tslog is inside extract_<job_id> directory
        extract_parent = tslog.parent
        if extract_parent.exists() and extract_parent.name.startswith("extract_"):
            shutil.rmtree(extract_parent, ignore_errors=True)

    # Remove archive file(s)
    for ext in ['.7z', '.zip', '.rar', '.tar.gz', '.tgz', '.tar']:
        archive = UPLOAD_DIR / f"{job_id}{ext}"
        if archive.exists():
            archive.unlink()

    # Remove cached reports
    for rp in REPORT_DIR.glob(f"{job_id}_*.json"):
        rp.unlink()

    # Remove from history
    history = load_history()
    history = [h for h in history if h["job_id"] != job_id]
    save_history(history)

    return JSONResponse({"job_id": job_id, "deleted": True})


@app.get("/api/download/{job_id}")
async def download_file(job_id: str):
    """下载原始上传的压缩包"""
    import shutil

    # Try all supported extensions
    for ext in ['.7z', '.zip', '.rar', '.tar.gz', '.tgz', '.tar']:
        archive = UPLOAD_DIR / f"{job_id}{ext}"
        if archive.exists():
            # Get original filename (or use the archive name as fallback)
            filename = None
            if job_id in jobs and jobs[job_id].get("filename"):
                filename = jobs[job_id]["filename"]
            else:
                # Look up from history
                history = load_history()
                for h in history:
                    if h.get("job_id") == job_id:
                        filename = h.get("filename") or h.get("name")
                        break
            if not filename:
                filename = archive.name

            from fastapi.responses import FileResponse
            return FileResponse(
                path=str(archive),
                filename=filename,
                media_type="application/octet-stream",
            )

    return JSONResponse({"error": "文件不存在或已被删除"}, status_code=404)


@app.post("/api/chat/{job_id}")
async def chat_endpoint(job_id: str, request: Request):
    """AI chat endpoint — Function Calling for Windows/Linux, context injection for BMC/other"""
    body = await request.json()
    user_message = body.get("message", "").strip()
    if not user_message:
        return JSONResponse({"error": "消息不能为空"}, status_code=400)

    if job_id not in jobs:
        return JSONResponse({"error": "任务不存在"}, status_code=404)

    tslog = _get_tslog(job_id)
    if not tslog:
        return JSONResponse({"error": "日志目录不存在，请重新上传"}, status_code=404)

    os_type = jobs[job_id].get("os_type", "unknown")

    # === BMC / other: context injection mode (fast, one-shot) ===
    if os_type in ("bmc", "other"):
        return await _chat_context_inject(job_id, user_message, tslog, os_type)

    # === Windows / Linux: Function Calling mode ===
    return await _chat_function_calling(job_id, user_message, tslog)


# ─── Hermes Agent Bridge ──────────────────────────────
HERMES_QUEUE = BASE_DIR / "hermes_queue"
HERMES_PENDING = HERMES_QUEUE / "pending"
HERMES_DONE = HERMES_QUEUE / "done"
HERMES_QUICK = HERMES_QUEUE / "quick"
HERMES_LOCK = HERMES_QUEUE / ".processing_lock"


def _process_hermes_request_bg(payload: dict, request_id: str, tslog: Path):
    """Process a deep analysis request immediately in background."""
    import subprocess
    try:
        # Simple lock: only one processing at a time
        lock_file = HERMES_LOCK
        if lock_file.exists():
            return  # Another process is already handling it

        lock_file.touch()
        try:
            message = payload.get("message", "").lower()
            os_type = payload.get("os_type", "unknown")

            # Determine what the user is asking about
            want_dump = any(w in message for w in ["dump", "蓝屏", "崩溃", "crash", "bugcheck", "bsod", "蓝"])
            want_disk = any(w in message for w in ["硬盘", "磁盘", "disk", "smart", "坏道", "健康"])
            want_error = any(w in message for w in ["报错", "错误", "error", "异常", "问题", "整体", "全部", "所有", "综合"])
            want_overview = not (want_dump or want_disk or want_error) or want_error

            reply_parts = []

            # ── System overview ──
            if want_overview or want_error:
                systeminfo = _find_read_file(tslog, ["systeminfo.txt", "systeminfo*", "Systeminfo*"])
                dxdiag = _find_read_file(tslog, ["dxdiag.txt", "dxdiag*", "DxDiag*"])

                if systeminfo:
                    hostname = re.search(r'主机名.*?(\S+)', systeminfo)
                    model = re.search(r'系统型号.*?(\S.+)', systeminfo)
                    cpu = re.search(r'\[01\].*?(Intel.*?Mhz)', systeminfo)
                    ram = re.search(r'物理内存总量.*?([\d,]+) MB', systeminfo)
                    bios = re.search(r'BIOS 版本.*?(\S.+)', systeminfo)

                    overview = []
                    if hostname: overview.append(f"**主机名**: {hostname.group(1)}")
                    if model: overview.append(f"**型号**: {model.group(1)}")
                    if cpu: overview.append(f"**CPU**: {cpu.group(1)}")
                    if ram: overview.append(f"**内存**: {ram.group(1)} MB")
                    if bios: overview.append(f"**BIOS**: {bios.group(1)}")
                    if overview:
                        reply_parts.append("## 📋 系统概览\n" + "\n".join(f"- {o}" for o in overview))

            # ── Crash/Dump analysis ──
            if want_dump or want_error:
                dumps = list((tslog / "osdump").glob("*.dmp")) if (tslog / "osdump").is_dir() else []
                minidumps = [d for d in dumps if d.name != "MEMORY.DMP"]

                # Check System.evtx for bugcheck events
                system_evtx = tslog / "oslog" / "System.evtx"
                crash_events = []
                bugcheck_code = ""
                if system_evtx.exists():
                    try:
                        for eid, level, ts_str, prov, root in iter_evtx(system_evtx, max_events=3000):
                            if eid == 1001:  # BugCheck
                                for child in root.iter():
                                    if child.tag.endswith('}Data') and child.get('Name') == 'param1':
                                        code = child.text or ""
                                        m = re.search(r'0x([0-9a-f]+)', code)
                                        if m:
                                            bugcheck_code = m.group(1)
                                crash_events.append({"type": "bugcheck", "code": bugcheck_code, "time": ts_str})
                            elif eid == 41:  # Kernel-Power
                                bugcheck = 0
                                for child in root.iter():
                                    if child.tag.endswith('}Data') and child.get('Name') == 'BugcheckCode':
                                        try:
                                            bugcheck = int(child.text or "0")
                                        except:
                                            pass
                                crash_events.append({"type": "power", "code": bugcheck, "time": ts_str})
                            if len(crash_events) >= 50:
                                break
                    except Exception:
                        pass

                if minidumps or bugcheck_code or crash_events:
                    dump_section = ["## 🔴 崩溃/Dump 分析"]
                    if minidumps:
                        dump_section.append(f"\n**Dump 文件**: {len(minidumps)} 个 minidump + MEMORY.DMP")
                    if bugcheck_code:
                        bugcheck_desc = {
                            "124": "WHEA_UNCORRECTABLE_ERROR (硬件错误)",
                            "9f": "DRIVER_POWER_STATE_FAILURE",
                            "133": "DPC_WATCHDOG_VIOLATION",
                            "1e": "KMODE_EXCEPTION_NOT_HANDLED",
                            "50": "PAGE_FAULT_IN_NONPAGED_AREA",
                            "7e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
                            "3b": "SYSTEM_SERVICE_EXCEPTION",
                            "d1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
                        }.get(bugcheck_code.lower(), f"BugCheck 0x{bugcheck_code}")
                        dump_section.append(f"\n**BugCheck**: 0x{bugcheck_code} — {bugcheck_desc}")

                    if crash_events:
                        crash_types = {}
                        for ce in crash_events:
                            ct = ce["type"]
                            crash_types[ct] = crash_types.get(ct, 0) + 1
                        dump_section.append(f"\n**崩溃统计**: BugCheck {crash_types.get('bugcheck', 0)} 次 / 异常断电 {crash_types.get('power', 0)} 次")

                    reply_parts.append("\n".join(dump_section))

            # ── Disk/SMART analysis ──
            if want_disk or want_error:
                smart = _find_read_file(tslog, ["SMARTINFO.txt", "smartinfo*", "SMART*"])
                if smart:
                    disk_issues = []
                    # Check for bad sectors
                    pending = re.findall(r'Current_Pending_Sector\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', smart)
                    uncorrect = re.findall(r'Offline_Uncorrectable\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', smart)
                    ata_errs = re.findall(r'ATA Error Count.*?(\d+)', smart)
                    realloc = re.findall(r'Reallocated_Sector_Ct\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)', smart)

                    if any(int(v) > 0 for v in pending):
                        disk_issues.append(f"🔴 **待映射坏扇区**: {', '.join(pending)} 个")
                    if any(int(v) > 0 for v in uncorrect):
                        disk_issues.append(f"🔴 **不可修复扇区**: {', '.join(uncorrect)} 个")
                    if any(int(v) > 5 for v in realloc):
                        disk_issues.append(f"🟡 **已重映射扇区**: {', '.join(realloc)} 个")
                    if any(int(v) > 0 for v in ata_errs):
                        disk_issues.append(f"🟡 **ATA 错误**: {', '.join(ata_errs)} 次")

                    # Uncountable shutdowns from NVMe
                    unsafe = re.findall(r'Unsafe Shutdowns:\s+(\d+)', smart)
                    if unsafe and any(int(v) > 100 for v in unsafe):
                        disk_issues.append(f"⚠️ **异常断电次数**: {max(int(v) for v in unsafe)} 次")

                    if disk_issues:
                        reply_parts.append("## 💾 磁盘健康\n" + "\n".join(f"- {d}" for d in disk_issues))

            # ── Event log errors ──
            if want_error:
                system_evtx = tslog / "oslog" / "System.evtx"
                if system_evtx.exists():
                    try:
                        err_count = {"Critical": 0, "Error": 0, "Warning": 0}
                        levels = {1: "Critical", 2: "Error", 3: "Warning"}
                        for eid, level, ts_str, prov, root in iter_evtx(system_evtx, max_events=5000):
                            if level in levels:
                                err_count[levels[level]] += 1
                        if err_count["Error"] + err_count["Critical"] > 0:
                            reply_parts.append(
                                "## 📝 系统事件\n"
                                f"- 🔴 Critical: {err_count['Critical']} 条 | Error: {err_count['Error']} 条\n"
                                f"- 🟡 Warning: {err_count['Warning']} 条"
                            )
                    except Exception:
                        pass

            # Determine if this is a complex question that needs AI
            complex_keywords = ["详细", "整体", "全部", "所有", "关联", "分析", "深入", "全面", "综合", "总结"]
            is_complex = any(w in message for w in complex_keywords)

            # ── Compile final reply ──
            if is_complex:
                # Complex questions: don't write quick result, let AI handle it
                reply = None  # signal: skip quick, wait for AI
            elif reply_parts:
                reply = "\n\n".join(reply_parts)
                reply += "\n\n---\n> 💡 快速诊断中，AI 深度分析正在后台处理，结果将自动更新..."
            else:
                reply = "🔍 正在读取日志文件进行深度分析..."

            # Write to QUICK (not DONE) — let the cron/Hermes Agent write the final DONE
            if reply is not None:
                HERMES_QUICK.mkdir(parents=True, exist_ok=True)
                quick_file = HERMES_QUICK / f"{request_id}.json"
                with open(quick_file, "w", encoding="utf-8") as f:
                    json.dump({"request_id": request_id, "reply": reply}, f, ensure_ascii=False, indent=2)

        finally:
            # Clean up lock, but do NOT delete pending — cron still needs it
            if lock_file.exists():
                lock_file.unlink()

    except Exception:
        import traceback
        traceback.print_exc()


def _find_read_file(tslog: Path, names: list) -> str:
    """Find and read a file by candidate names."""
    for name in names:
        for path in tslog.rglob(name):
            if path.is_file():
                try:
                    with open(path, 'r', encoding='utf-8', errors='replace') as f:
                        return f.read(min(path.stat().st_size, 500 * 1024))
                except Exception:
                    pass
    return ""


@app.post("/api/chat-hermes/{job_id}")
async def chat_hermes_submit(job_id: str, body: dict):
    """Submit a chat request to the Hermes Agent bridge."""
    if job_id not in jobs:
        return JSONResponse({"error": "任务不存在"}, status_code=404)

    message = body.get("message", "").strip()
    if not message:
        return JSONResponse({"error": "消息不能为空"}, status_code=400)

    tslog = _get_tslog(job_id)
    if not tslog:
        return JSONResponse({"error": "日志目录不存在"}, status_code=404)

    request_id = str(uuid.uuid4())[:12]
    ts = datetime.now(CHINA_TZ).isoformat()

    # Gather context: list of available files
    file_list = []
    for f in sorted(Path(tslog).rglob("*")):
        if f.is_file():
            try:
                file_list.append({
                    "path": str(f.relative_to(tslog)),
                    "size": f.stat().st_size,
                    "suffix": f.suffix.lower()
                })
            except OSError:
                pass

    payload = {
        "request_id": request_id,
        "job_id": job_id,
        "message": message,
        "os_type": jobs[job_id].get("os_type", "unknown"),
        "tslog_path": str(tslog),
        "files": file_list[:200],  # cap at 200 files
        "created_at": ts,
    }

    HERMES_PENDING.mkdir(parents=True, exist_ok=True)
    req_file = HERMES_PENDING / f"{request_id}.json"
    with open(req_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    # Immediately start background analysis (don't wait for cron)
    thread = threading.Thread(
        target=_process_hermes_request_bg,
        args=(payload, request_id, tslog),
        daemon=True)
    thread.start()

    return JSONResponse({"request_id": request_id, "status": "pending"})


@app.get("/api/chat-hermes/{job_id}/poll")
async def chat_hermes_poll(job_id: str, rid: str = ""):
    """Poll for Hermes bridge response."""
    if not rid:
        return JSONResponse({"status": "pending", "hint": "no request_id"})

    HERMES_DONE.mkdir(parents=True, exist_ok=True)
    done_file = HERMES_DONE / f"{rid}.json"
    if done_file.exists():
        try:
            with open(done_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return JSONResponse({"status": "done", "reply": data.get("reply", "")})
        except Exception:
            pass

    # Check for quick analysis fallback
    quick_file = HERMES_QUICK / f"{rid}.json"
    if quick_file.exists():
        try:
            with open(quick_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return JSONResponse({"status": "quick", "reply": data.get("reply", "")})
        except Exception:
            pass

    # Check if still pending
    pending_file = HERMES_PENDING / f"{rid}.json"
    if pending_file.exists():
        return JSONResponse({"status": "pending"})

    return JSONResponse({"status": "expired", "hint": "request not found"})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8002)
