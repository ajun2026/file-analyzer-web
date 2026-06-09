"""Context injection chat for BMC/Other."""
import httpx
from pathlib import Path
from fastapi.responses import JSONResponse
from detectors import detect_encoding

async def _chat_context_inject(job_id: str, user_message: str, tslog, os_type: str):
    """Context injection mode for BMC/other — gather all readable files, inject as system prompt, one-shot."""

    # Gather all readable text files from the log directory
    files_context = ""
    text_paths = []

    # BMC critical log files (priority-sorted, from file-analyzer-web)
    bmc_critical = ['bmc-err.log', 'kernel-err.log', 'ffdc.log', 'component_activity.log',
                    'kernel.log', 'bmc-warn.log', 'xcc_pl_error.log', 'pfr_device.log']
    bmc_important = ['syshealth.log', 'security.log', 'system.log', 'bmc-loop.log',
                     'syshealth-crit.log', 'security.boot.log', 'hostlog.log', 'ffdc_live_dbg']

    if tslog.is_dir():
        # Collect all files recursively
        all_files = []
        for f in tslog.rglob("*"):
            if f.is_file():
                all_files.append(f)

        total_files = len(all_files)
        files_context = f"【文件清单 — 共 {total_files} 个文件】\n"

        def file_priority(fp):
            name = fp.name.lower()
            if name in bmc_critical:
                return 0
            if name in bmc_important:
                return 1
            if name.endswith('.log'):
                return 2
            ext = fp.suffix.lower()
            if ext in ('.txt', '.cfg', '.conf', '.ini', '.json', '.xml', '.csv', '.md'):
                return 3
            return 4

        all_files.sort(key=file_priority)

        dirs_seen = set()
        for fp in all_files:
            try:
                rel = str(fp.relative_to(tslog))
            except ValueError:
                rel = fp.name
            parent = str(fp.parent.relative_to(tslog)) if fp.parent != tslog else "."
            if parent not in dirs_seen:
                files_context += f"\n📁 {parent}/\n"
                dirs_seen.add(parent)
            files_context += f"    - {fp.name}\n"

        # Collect readable text paths
        text_exts = {'.txt', '.log', '.cfg', '.conf', '.ini', '.json', '.xml', '.csv',
                     '.md', '.yml', '.yaml', '.toml', '.env', '.sh'}
        for fp in all_files:
            if fp.suffix.lower() in text_exts or fp.name.lower() in ('makefile', 'dockerfile'):
                text_paths.append(fp)
            elif fp.suffix == '':
                try:
                    with open(fp, 'rb') as test_f:
                        head = test_f.read(512)
                    printable = sum(1 for b in head if 0x20 <= b <= 0x7E or b in (0x0A, 0x0D, 0x09))
                    if len(head) > 0 and printable / len(head) > 0.90:
                        text_paths.append(fp)
                except Exception:
                    pass

        # Load file contents (key files 10KB, others 5KB, total cap 1.5MB)
        files_context += "\n\n【文件内容摘要】\n"
        total_chars = len(files_context)
        max_chars = 1500000

        for fp in text_paths:
            if total_chars >= max_chars:
                break
            try:
                rel = str(fp.relative_to(tslog))
            except ValueError:
                rel = fp.name
            is_key = fp.name.lower() in bmc_critical + bmc_important
            per_file_max = 10240 if is_key else 5120

            try:
                enc = detect_encoding(fp)
                with open(fp, 'r', encoding=enc, errors='replace') as fh:
                    raw = fh.read()
                chunk = raw[:min(per_file_max, max_chars - total_chars)]
                files_context += f"\n=== {rel} ===\n{chunk}\n"
                total_chars += len(chunk) + len(rel) + 20
            except Exception:
                continue

    # Build system prompt with context
    bmc_label = "BMC/XCC 诊断" if os_type == "bmc" else ""
    system_prompt = (
        f"你是一个专业的日志分析助手。用户上传了一批{bmc_label}文件，"
        f"你需要基于这些文件内容来回答用户的问题。\n\n"
        f"以下是上传文件的内容摘要：\n{files_context}\n\n"
        f"请基于以上文件内容，用中文回答用户的问题。"
        f"如果问题与文件内容无关，可以结合你的知识回答。回答要清晰、结构化。"
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    try:
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
                    "temperature": 0.7,
                    "max_tokens": 8192,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            reply = data["choices"][0]["message"]["content"]
            return JSONResponse({"reply": reply})

    except httpx.HTTPStatusError as e:
        return JSONResponse(
            {"error": f"API 调用失败: {e.response.status_code} - {e.response.text[:200]}"},
            status_code=502)
    except Exception as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=500)
