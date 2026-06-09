#!/usr/bin/env python3.12
"""
Thinkstation 日志诊断分析系统 - FastAPI 后端 v3
改进：上传后按需分析，点击选项才触发后台处理
"""
import json
import os
import uuid
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import Counter
from typing import Optional

from fastapi import FastAPI, File, Form, UploadFile, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import jinja2
import aiofiles
import httpx

# ─── Configuration ───────────────────────────────────────────
BASE_DIR = Path("/opt/log-analyzer")
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

for d in [UPLOAD_DIR, REPORT_DIR, TEMPLATE_DIR, STATIC_DIR]:
    d.mkdir(parents=True, exist_ok=True)

jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=True,
)

app = FastAPI(title="Thinkstation 日志诊断分析系统", version="0.3.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ─── In-memory job tracker ──────────────────────────────────
jobs: dict = {}
CHINA_TZ = timezone(timedelta(hours=8))
HISTORY_FILE = REPORT_DIR / "history.json"

def load_history() -> list:
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_history(history: list):
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(history, f, ensure_ascii=False, indent=2)

def add_to_history(job_id: str, filename: str, size: float, evtx_count: int, tslog_path: str = None, os_type: str = "windows", sn: str = ""):
    history = load_history()
    now = datetime.now(CHINA_TZ).isoformat()
    # Count files
    total_files = 0
    siolog_exists = False
    dump_exists = False
    if tslog_path and Path(tslog_path).exists():
        total_files = sum(1 for _ in Path(tslog_path).rglob('*') if _.is_file())
        siolog_exists = (Path(tslog_path) / "SIO_Events.log").exists()
        dump_exists = (Path(tslog_path) / "osdump").is_dir() and any(
            (Path(tslog_path) / "osdump").iterdir())
    history.insert(0, {
        "job_id": job_id,
        "name": filename,
        "filename": filename,
        "size_mb": size,
        "evtx_count": evtx_count,
        "total_files": total_files,
        "siolog": siolog_exists,
        "dump": dump_exists,
        "os_type": os_type,
        "sn": sn,
        "created_at": now,
    })
    # Keep only last 50 entries
    save_history(history[:50])


# ─── Utils ───────────────────────────────────────────────────
def detect_encoding(filepath: Path) -> str:
    for enc in ['gbk', 'utf-16-le', 'utf-8']:
        try:
            with open(filepath, 'r', encoding=enc) as f:
                f.read(1024)
            return enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    return 'latin-1'

def extract_archive(filepath: Path) -> Path:
    extract_dir = filepath.parent / f"extract_{filepath.stem}"
    if extract_dir.exists():
        return extract_dir  # already extracted
    extract_dir.mkdir(exist_ok=True)
    filename = filepath.name.lower()
    # .tzz: lzop-compressed tar (IBM/Lenovo XCC FFDC format)
    if filename.endswith('.tzz'):
        subprocess.run(['tar', '--lzop', '-xf', str(filepath), '-C', str(extract_dir)],
                       capture_output=True, timeout=300)
        return extract_dir
    # tar.gz / tgz / tar
    if filename.endswith('.tar.gz') or filename.endswith('.tgz') or filename.endswith('.tar'):
        subprocess.run(['tar', 'xzf' if filename.endswith(('gz', 'tgz')) else 'xf',
                        str(filepath), '-C', str(extract_dir)],
                       capture_output=True, timeout=180)
        return extract_dir
    ext = filepath.suffix.lower()
    if ext == '.7z':
        subprocess.run(['7z', 'x', '-y', str(filepath), f'-o{extract_dir}'],
                       capture_output=True, timeout=120)
    else:
        result = subprocess.run(['unzip', '-o', str(filepath), '-d', str(extract_dir)],
                                capture_output=True, timeout=120)
        if result.returncode != 0:
            subprocess.run(['7z', 'x', '-y', str(filepath), f'-o{extract_dir}'],
                           capture_output=True, timeout=120)
    return extract_dir

def find_log_dir(extract_dir: Path) -> tuple[Optional[Path], str]:
    """Returns (log_dir_path, os_type) where os_type is 'windows', 'linux', 'bmc', or 'other'"""
    # ── 1. Windows: look for tslog/ or oslog/ ──
    tslog = extract_dir / "tslog"
    if tslog.is_dir():
        return tslog, "windows"
    for path in extract_dir.rglob("tslog"):
        if path.is_dir():
            return path, "windows"
    if (extract_dir / "oslog").is_dir():
        return extract_dir, "windows"

    # ── 2. BMC / XCC FFDC: detect BEFORE Linux because BMC packages
    #       often contain var/log/ from the BMC's internal Linux filesystem ──
    bmc_markers = ['ffdc.log', 'bmc-err.log', 'kernel-err.log',
                   'component_activity.log', 'syshealth.log',
                   'security.log', 'system.log', 'bmc-warn.log',
                   'xcc_pl_error.log', 'pfr_device.log', 'bmc-loop.log']
    for marker in bmc_markers:
        # Recursive search: BMC markers can be deep inside tmp/ etc.
        for found in extract_dir.rglob(marker):
            if found.is_file():
                return extract_dir, "bmc"  # Return full extract dir for BMC

    # ── 3. Windows fallback: scan for .evtx or .dmp files ──
    for path in extract_dir.rglob("*.evtx"):
        parent = path.parent
        if parent == extract_dir:
            return extract_dir, "windows"
        for candidate in extract_dir.iterdir():
            if candidate.is_dir() and path.is_relative_to(candidate):
                return candidate, "windows"
    for path in extract_dir.rglob("*.dmp"):
        parent = path.parent
        if parent == extract_dir:
            return extract_dir, "windows"
        for candidate in extract_dir.iterdir():
            if candidate.is_dir() and path.is_relative_to(candidate):
                return candidate, "windows"

    # ── 4. Linux: look for var/log/ or syslog/kern.log files ──
    varlog = extract_dir / "var" / "log"
    if varlog.is_dir():
        return varlog, "linux"
    for path in extract_dir.rglob("var/log"):
        if path.is_dir():
            return path, "linux"
    for fname in ['syslog', 'kern.log', 'messages', 'dmesg', 'auth.log']:
        if (extract_dir / fname).is_file():
            return extract_dir, "linux"

    # ── 5. Generic fallback: any .log/.txt files → "other" ──
    generic_log_markers = ['*.log', '*.txt']
    for pattern in generic_log_markers:
        if list(extract_dir.glob(pattern)):
            return extract_dir, "other"
        for child in extract_dir.iterdir():
            if child.is_dir() and list(child.glob(pattern)):
                return child, "other"
    return None, "unknown"


def normalize_log_structure(log_dir: Path) -> None:
    """Create oslog / osdump symlinks for non-standard Windows log structures."""
    if not log_dir or not log_dir.is_dir():
        return
    # Check if oslog/ already exists
    oslog = log_dir / "oslog"
    if not oslog.exists():
        # Look for alternative evtx directories (direct children)
        for name in ['Logs', 'logs', 'evtx', 'EventLogs', '事件日志']:
            alt = log_dir / name
            if alt.is_dir() and any(alt.glob("*.evtx")):
                alt.rename(oslog)
                break
        else:
            # If evtx files directly in log_dir, create oslog with symlinks
            if any(log_dir.glob("*.evtx")):
                os.makedirs(oslog, exist_ok=True)
                for evtx in log_dir.glob("*.evtx"):
                    (oslog / evtx.name).symlink_to(evtx.resolve())
            else:
                # Recursive fallback: find ALL .evtx files anywhere, symlink into oslog/
                evtx_dirs = set()
                for evtx in log_dir.rglob("*.evtx"):
                    evtx_dirs.add(evtx.parent)
                if evtx_dirs:
                    os.makedirs(oslog, exist_ok=True)
                    for d in evtx_dirs:
                        for evtx in d.glob("*.evtx"):
                            target = oslog / evtx.name
                            if target.exists():
                                # Name collision → prefix with parent dir name
                                target = oslog / f"{d.name}_{evtx.name}"
                            target.symlink_to(evtx.resolve())
    # Check if osdump/ already exists
    osdump = log_dir / "osdump"
    if not osdump.exists():
        for name in ['蓝屏', 'dump', 'dumps', 'Minidump', 'minidump', 'crash']:
            alt = log_dir / name
            if alt.is_dir() and any(alt.glob("*.dmp")):
                alt.rename(osdump)
                break
        else:
            # Recursive fallback for .dmp files
            dmp_dirs = set()
            for dmp in log_dir.rglob("*.dmp"):
                dmp_dirs.add(dmp.parent)
            if dmp_dirs:
                os.makedirs(osdump, exist_ok=True)
                for d in dmp_dirs:
                    for dmp_file in d.glob("*.dmp"):
                        target = osdump / dmp_file.name
                        if target.exists():
                            target = osdump / f"{d.name}_{dmp_file.name}"
                        target.symlink_to(dmp_file.resolve())


def find_tslog_dir(extract_dir: Path) -> Optional[Path]:
    """Backward compat wrapper"""
    d, _ = find_log_dir(extract_dir)
    return d


# ─── EVTX Helpers ────────────────────────────────────────────
MAX_EVENTS = 10000
REBOOT_IDS = {12, 13, 19, 41, 1001, 1074, 6005, 6008, 6009, 7045}
EVENT_DESC = {
    41: "Kernel-Power：意外断电", 6008: "EventLog：上次关机意外",
    1074: "User32：进程发起关机", 1001: "BugCheck：蓝屏事件",
    6005: "事件日志服务启动", 6009: "事件日志服务启动",
    12: "系统启动", 13: "系统关闭",
}
LKE_CODES = {
    "141": "GPU 视频引擎超时 (TDR)", "144": "USB3 设备错误",
    "117": "显卡驱动停止响应", "17d": "硬件错误 (WHEA)",
    "1a8": "磁盘 I/O 内核错误", "193": "驱动超时",
    "1b8": "显卡 Miniport 驱动错误",
}

def iter_evtx(evtx_path: Path, max_events: int = MAX_EVENTS):
    """Generator: yield (event_id, level, timestamp, provider, lxml_root) for each record."""
    from Evtx.Evtx import Evtx
    from lxml import etree
    NS = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    count = 0
    try:
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                count += 1
                if count > max_events:
                    break
                try:
                    root = etree.fromstring(record.xml().encode())
                    eid_el = root.find('.//ns:EventID', NS)
                    eid = int(eid_el.text) if eid_el is not None and eid_el.text else 0
                    lvl_el = root.find('.//ns:Level', NS)
                    lvl = int(lvl_el.text) if lvl_el is not None and lvl_el.text else 0
                    ts_el = root.find('.//ns:TimeCreated', NS)
                    ts = ts_el.get('SystemTime', '') if ts_el is not None else ''
                    prov_el = root.find('.//ns:Provider', NS)
                    prov = prov_el.get('Name', '') if prov_el is not None else ''
                    yield eid, lvl, ts, prov, root
                except Exception:
                    yield 0, 0, '', '', None
    except Exception:
        pass


# ─── Analysis Functions ──────────────────────────────────────

def analyze_overview(tslog: Path) -> dict:
    """📊 系统概览：结构化提取硬件/OS/软件信息"""
    import re

    def read_text(filename: str) -> str:
        fp = tslog / filename
        if not fp.exists():
            return ""
        enc = detect_encoding(fp)
        try:
            with open(fp, 'r', encoding=enc, errors='replace') as f:
                return f.read()
        except Exception:
            return ""

    # ── Parse Systeminfo.txt ──
    sysinfo = read_text("Systeminfo.txt")
    sys_fields = {}
    field_map = {
        "hostname": r'主机名:\s+(.+)',
        "os_name": r'OS 名称:\s+(.+)',
        "os_version": r'OS 版本:\s+(.+)',
        "os_manufacturer": r'OS 制造商:\s+(.+)',
        "os_config": r'OS 配置:\s+(.+)',
        "registered_owner": r'注册的所有人:\s+(.+)',
        "registered_org": r'注册的组织:\s+(.+)',
        "install_date": r'初始安装日期:\s+(.+)',
        "boot_time": r'系统启动时间:\s+(.+)',
        "manufacturer": r'系统制造商:\s+(.+)',
        "model": r'系统型号:\s+(.+)',
        "system_type": r'系统类型:\s+(.+)',
        "bios_version": r'BIOS 版本:\s+(.+)',
        "total_memory": r'物理内存总量:\s+([\d,]+)',
        "available_memory": r'可用的物理内存:\s+([\d,]+)',
        "domain": r'域:\s+(.+)',
        "timezone": r'时区:\s+(.+)',
    }
    for key, pattern in field_map.items():
        m = re.search(pattern, sysinfo)
        if m:
            sys_fields[key] = m.group(1).strip()

    # Extract CPU — prefer dxdiag.txt (more descriptive) over Systeminfo.txt [01]
    dxdiag = read_text("dxdiag.txt")
    dx_cpu_match = re.search(r'Processor:\s*(.+)', dxdiag)
    if dx_cpu_match:
        sys_fields["cpu"] = dx_cpu_match.group(1).strip()

    if not sys_fields.get("cpu"):
        cpu_match = re.search(r'\[01\]:\s*(.+)', sysinfo)
        if cpu_match:
            sys_fields["cpu"] = cpu_match.group(1).strip()

    # Extract NICs (only after "网卡:" header, line-by-line)
    nics = []
    nic_section_idx = sysinfo.find("网卡:")
    if nic_section_idx >= 0:
        nic_section = sysinfo[nic_section_idx:]
        current_nic = None
        in_ips = False
        for line in nic_section.split('\n'):
            # Match NIC entry: [0X]: name (at same indent as "网卡:")
            m = re.match(r'\s{18}\[(\d{2})\]:\s*(.+)', line)
            if m:
                name = m.group(2).strip()
                if re.match(r'(KB\d+|\d{1,3}\.)', name):
                    continue  # Skip hotfix/IP entries
                if current_nic:
                    nics.append(current_nic)
                current_nic = {"name": name, "status": "?", "dhcp": "?", "ips": []}
                in_ips = False
                continue
            if not current_nic:
                continue
            # Match status
            sm = re.search(r'状态:\s*(.+)', line)
            if sm: current_nic["status"] = sm.group(1).strip()
            # Match DHCP
            dm = re.search(r'启用 DHCP:\s*(.+)', line)
            if dm: current_nic["dhcp"] = dm.group(1).strip()
            # IP section
            if 'IP 地址' in line:
                in_ips = True
                continue
            if in_ips:
                ipm = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ipm:
                    current_nic["ips"].append(ipm.group(1))
        if current_nic:
            nics.append(current_nic)
    sys_fields["nics"] = nics
    sys_fields["nic_count"] = len(nics)

    # ── Parse dxdiag.txt ──
    # (dxdiag already loaded above for CPU)
    gpu = {}
    gpu_m = re.search(r'Card name:\s*(.+)', dxdiag)
    if gpu_m: gpu["name"] = gpu_m.group(1).strip()
    gpu_m2 = re.search(r'Chip type:\s*(.+)', dxdiag)
    if gpu_m2: gpu["chip"] = gpu_m2.group(1).strip()
    gpu_m3 = re.search(r'Display Memory:\s*(.+)', dxdiag)
    if gpu_m3: gpu["display_memory"] = gpu_m3.group(1).strip()
    gpu_m4 = re.search(r'Dedicated Memory:\s*(.+)', dxdiag)
    if gpu_m4: gpu["dedicated_memory"] = gpu_m4.group(1).strip()
    gpu_m5 = re.search(r'Current Mode:\s*(.+)', dxdiag)
    if gpu_m5: gpu["current_mode"] = gpu_m5.group(1).strip()
    gpu_m6 = re.search(r'Driver Version:\s*(.+?)\s*$', dxdiag, re.MULTILINE)
    if gpu_m6: gpu["driver_version"] = gpu_m6.group(1).strip()
    gpu_m7 = re.search(r'Driver Date/Size:\s*([\d/]+)', dxdiag)
    if gpu_m7: gpu["driver_date"] = gpu_m7.group(1).strip()

    # ── Parse SMARTINFO.txt ──
    smart = read_text("SMARTINFO.txt")
    disks = []
    for disk_match in re.finditer(r'=== START OF INFORMATION SECTION ===\n(.*?)(?=\n\n|$)',
                                   smart, re.DOTALL):
        block = disk_match.group(1)
        disk = {}
        for lbl, pat in [("vendor", r'Vendor:\s*(.+)'),
                         ("model", r'(?:Device Model|Product|Model Number):\s*(.+)'),
                         ("serial", r'Serial Number:\s*(.+)'),
                         ("capacity", r'User Capacity:\s*(.+)'),
                         ("rpm", r'Rotation Rate:\s*(.+)'),
                         ("firmware", r'(?:Firmware Version|Revision):\s*(.+)'),
                         ("smart", r'SMART support is:\s*(.+)')]:
            m = re.search(pat, block)
            if m: disk[lbl] = m.group(1).strip()
        if disk:
            disks.append(disk)

    # ── Parse SIO_Events.log ──
    sio_content = read_text("SIO_Events.log")
    sio_info = {}
    for lbl, pat in [("product_id", r'SIO Product ID = (.+)'),
                     ("firmware", r'SIO Firmware Version = (.+)'),
                     ("event_count", r'Event Num = (\d+)')]:
        m = re.search(pat, sio_content)
        if m: sio_info[lbl] = m.group(1).strip()

    # ── File list ──
    text_files = {}
    for f in sorted(tslog.iterdir()):
        if f.suffix.lower() in ('.txt', '.log') and f.stat().st_size > 0:
            text_files[f.name] = {"filename": f.name, "size": f.stat().st_size}

    evtx_dir = tslog / "oslog"
    evtx_count = len(list(evtx_dir.glob("*.evtx"))) if evtx_dir.is_dir() else 0

    return {
        "title": "📊 系统概览",
        "system": sys_fields,
        "gpu": gpu,
        "disks": disks,
        "sio": sio_info,
        "evtx_count": evtx_count,
        "text_files": text_files,
        "text_file_count": len(text_files),
    }


def analyze_reboot(tslog: Path) -> dict:
    """⚡ 意外重启分析"""
    evtx_dir = tslog / "oslog"
    system_evtx = evtx_dir / "System.evtx"
    if not system_evtx.exists():
        return {"title": "⚡ 重启分析", "error": "System.evtx 未找到"}

    events_41 = []
    events_6008 = []
    all_found = []

    for eid, lvl, ts, prov, root in iter_evtx(system_evtx):
        if eid not in REBOOT_IDS:
            continue
        entry = {"id": eid, "time": ts, "level": lvl,
                 "provider": prov, "description": EVENT_DESC.get(eid, '')}
        all_found.append(entry)
        if eid == 41:
            events_41.append(entry)
        elif eid == 6008:
            events_6008.append(entry)

    return {
        "title": "⚡ 意外重启分析（微软官方诊断标准）",
        "unexpected_shutdowns_count": len(events_41),
        "unexpected_shutdowns": sorted(events_41, key=lambda x: x['time'], reverse=True),
        "event_6008_count": len(events_6008),
        "all_reboot_events": all_found,
        "summary": f"发现 {len(events_41)} 次意外断电 (Event 41), {len(events_6008)} 次意外关机记录",
    }


def analyze_hardware(tslog: Path) -> dict:
    """🔧 硬件诊断：LiveKernelEvent + SMART + NVIDIA"""
    evtx_dir = tslog / "oslog"
    app_evtx = evtx_dir / "Application.evtx"

    lke_events = []
    if app_evtx.exists():
        import re
        for eid, lvl, ts, prov, root in iter_evtx(app_evtx):
            if eid != 1001:
                continue
            data_items = root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data')
            combined = '\n'.join([(d.text or '') for d in data_items])
            if 'LiveKernelEvent' not in combined:
                continue
            # Extract LKE code from Data element with name="P1"
            code = '?'
            for d in data_items:
                if d.get('Name') == 'P1' and d.text:
                    code = d.text.strip()
                    break
            lke_events.append({
                "code": code,
                "description": LKE_CODES.get(code, f"未知: {code}"),
                "time": ts,
            })

    # Read SMART / NVIDIA text files
    extra = {}
    for name in ['SMARTINFO.txt', 'NVIDIA_INFO.txt', 'Partitions.txt']:
        fp = tslog / name
        if fp.exists() and fp.stat().st_size > 0:
            enc = detect_encoding(fp)
            try:
                with open(fp, 'r', encoding=enc, errors='replace') as f:
                    extra[name] = f.read()[:2000]
            except Exception:
                pass

    return {
        "title": "🔧 硬件诊断",
        "lke_events": lke_events,
        "lke_count": len(lke_events),
        "extra": extra,
    }


def analyze_events(tslog: Path) -> dict:
    """📝 事件日志：System/Application/Security 分布 + 错误"""
    evtx_dir = tslog / "oslog"
    if not evtx_dir.is_dir():
        return {"title": "📝 事件日志", "error": "oslog 目录未找到"}

    results = {}
    evtx_files = sorted(evtx_dir.glob("*.evtx"), key=lambda p: p.stat().st_size, reverse=True)
    # Only analyze top 6 largest files to keep performance reasonable
    evtx_files = evtx_files[:6]

    for logpath in evtx_files:
        name = logpath.name
        counter = Counter()
        errors = []
        total = 0
        for eid, lvl, ts, prov, root in iter_evtx(logpath, max_events=1000):
            total += 1
            counter[eid] += 1
            if lvl <= 2 and len(errors) < 50 and root is not None:
                data = []
                for d in root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                    if d.text and d.text.strip():
                        data.append(f"{d.get('Name','')}: {d.text[:100]}")
                errors.append({"id": eid, "time": ts, "level": lvl, "provider": prov, "data": data[:3]})

        results[name] = {
            "total": total,
            "distribution": dict(counter.most_common(20)),
            "errors": errors,
        }

    return {
        "title": "📝 事件日志分析",
        "total_files": len(evtx_files),
        "total_available": len(list(evtx_dir.glob("*.evtx"))),
        "logs": results,
    }


def analyze_system_diagnostics(tslog: Path) -> dict:
    """📋 系统诊断（微软标准）：硬件告警 → 重启分析 → 事件分布

    参考：https://learn.microsoft.com/zh-cn/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs

    分析流程：
      1. 扫描 System.evtx 提取硬件告警（磁盘、WHEA、驱动错误）
      2. 按微软标准重建重启时间线（Event 12,13,19,41,1001,1074,6008,6009,7045）
      3. 关联分析：驱动/服务安装 → 后续崩溃
      4. 事件分布统计（System.evtx + Application.evtx）
      5. Application.evtx 中 LiveKernelEvent 提取
    """
    import re
    from collections import defaultdict

    evtx_dir = tslog / "oslog"
    system_evtx = evtx_dir / "System.evtx"
    app_evtx = evtx_dir / "Application.evtx"

    # ── 硬件错误事件 ID 定义 ──
    HW_ERROR_IDS = {
        7:   "磁盘坏块", 11: "磁盘控制器错误",
        15:  "磁盘未就绪", 17: "WHEA 硬件错误",
        18:  "WHEA 已纠正错误", 19: "Windows Update",
        20:  "Windows Update 安装失败", 51: "磁盘分页错误",
        52:  "磁盘自检 (SMART) 警告", 55: "NTFS 结构损坏",
        137: "内核电源错误", 153: "磁盘控制器重试",
        157: "磁盘意外移除", 219: "驱动加载失败",
        220: "驱动启动失败",
    }

    # ── 重启/关机事件 MS 官方标准 ──
    RESTART_IDS = {
        12:   ("Kernel-General", "系统启动"),
        13:   ("Kernel-General", "系统关闭"),
        19:   ("WindowsUpdateClient", "Windows Update 安装"),
        41:   ("Kernel-Power", "意外断电/强制关机"),
        1001: ("WER-SystemErrorReport", "BugCheck 蓝屏"),
        1074: ("User32", "用户/进程发起关机"),
        6005: ("EventLog", "事件日志服务已启动"),
        6008: ("EventLog", "上次系统关闭是意外的"),
        6009: ("EventLog", "操作系统已启动"),
        7045: ("Service Control Manager", "服务已安装"),
    }

    # ── Events to track ──
    hardware_errors = []        # 硬件告警事件
    restart_events = []         # 重启相关事件（含驱动安装）
    syst_dist = defaultdict(int)  # System.evtx 事件分布
    syst_total = 0
    app_dist = defaultdict(int)  # Application.evtx 分布
    app_total = 0
    lke_events = []             # LiveKernelEvent

    # ═══ Pass 1: System.evtx (one pass for everything) ═══
    if system_evtx.exists():
        # Track service/update installations near crashes
        recent_installs = []  # [(time, event_id, desc)]
        crash_events = []     # [(time, event_id, desc)]

        for eid, lvl, ts, prov, root in iter_evtx(system_evtx, max_events=5000):
            syst_total += 1
            syst_dist[eid] += 1

            # ── Hardware errors ──
            if eid in HW_ERROR_IDS and lvl <= 3:
                entry = {"id": eid, "time": ts, "level": lvl, "provider": prov,
                         "description": HW_ERROR_IDS.get(eid, ''), "details": []}
                if root is not None:
                    for d in root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                        if d.text and d.text.strip() and len(entry['details']) < 4:
                            entry['details'].append(d.text.strip()[:150])
                # Only keep severity 1-2 errors; level 3 as warnings
                if lvl <= 2 or eid in (55, 153, 7, 51):  # always record disk errors
                    hardware_errors.append(entry)

            # ── Restart / shutdown events ──
            if eid in RESTART_IDS:
                evt = {"id": eid, "time": ts, "provider": prov,
                       "description": RESTART_IDS.get(eid, ('', ''))[1],
                       "source": RESTART_IDS.get(eid, ('', ''))[0]}
                # Extract extra details for key events
                if root is not None:
                    data_items = root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data')
                    if eid == 1074:
                        for d in data_items:
                            name = d.get('Name', '')
                            text = (d.text or '').strip()
                            if name == 'param1' and text:
                                evt['process'] = text
                            elif name == 'param4' and text:
                                evt['reason'] = text
                            elif name == 'param7' and text:
                                evt['reason_code'] = text
                    elif eid == 1001:
                        for d in data_items:
                            name = d.get('Name', '')
                            text = (d.text or '').strip()
                            if name == 'BugcheckCode' and text:
                                try:
                                    code = int(text)
                                    evt['bugcheck_code'] = code
                                    evt['bugcheck'] = get_bugcheck_info(code)
                                except ValueError:
                                    pass
                            elif name == 'BugcheckParameter1':
                                evt['param1'] = text
                    elif eid == 7045:
                        for d in data_items:
                            name = d.get('Name', '')
                            text = (d.text or '').strip()
                            if name == 'ServiceName' and text:
                                evt['service_name'] = text
                            elif name == 'ServiceFileName' and text:
                                evt['service_file'] = text.rsplit('\\', 1)[-1] if '\\' in text else text
                    elif eid == 19:
                        for d in data_items:
                            text = (d.text or '').strip()
                            if text and 'KB' in text:
                                evt['update_kb'] = text[:100]
                                break
                restart_events.append(evt)
                # Track installs before crashes
                if eid == 7045:
                    recent_installs.append(evt)
                elif eid in (41, 1001):
                    crash_events.append(evt)

    # ── Hardware error summary ──
    hw_by_type = defaultdict(list)
    for err in hardware_errors:
        hw_by_type[err['id']].append(err)

    # ── Cross-reference: installs before crashes ──
    correlated = []
    for crash in crash_events:
        crash_ts = crash.get('time', '')
        preceding = []
        for inst in recent_installs:
            inst_ts = inst.get('time', '')
            if inst_ts and crash_ts and inst_ts < crash_ts:
                try:
                    c_dt = datetime.fromisoformat(crash_ts.replace('Z', '+00:00'))
                    i_dt = datetime.fromisoformat(inst_ts.replace('Z', '+00:00'))
                    if (c_dt - i_dt).total_seconds() < 600:  # within 10 minutes
                        preceding.append(inst)
                except Exception:
                    pass
        if preceding:
            correlated.append({"crash": crash, "preceding_installs": preceding})

    # ═══ Pass 2: Application.evtx ═══
    if app_evtx.exists():
        for eid, lvl, ts, prov, root in iter_evtx(app_evtx, max_events=2000):
            app_total += 1
            app_dist[eid] += 1
            # LiveKernelEvent extraction
            if eid == 1001:
                data_items = root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data')
                combined = '\n'.join([(d.text or '') for d in data_items])
                if 'LiveKernelEvent' in combined:
                    # Extract LKE code from Data element with name="P1"
                    # Real structure: Data[name=EventName]=LiveKernelEvent, Data[name=P1]=1a8
                    code = '?'
                    for d in data_items:
                        if d.get('Name') == 'P1' and d.text:
                            code = d.text.strip()
                            break
                    lke_events.append({
                        "code": code,
                        "description": LKE_CODES.get(code, f"未知: {code}"),
                        "time": ts,
                    })

    # ═══ Pass 3: Dump file bugcheck extraction ═══
    # Scan .dmp files for bugcheck codes when evtx Event 1001 is missing
    dump_bugchecks = []
    dump_dir = tslog / "osdump"
    if dump_dir.is_dir():
        import struct as _struct
        for dp in sorted(dump_dir.iterdir()):
            if dp.suffix.lower() != '.dmp':
                continue
            if dp.stat().st_size == 0:
                continue
            try:
                with open(dp, 'rb') as fh:
                    header = fh.read(0x200)
                sig = _struct.unpack_from('<I', header, 0)[0] if len(header) >= 4 else 0
                bugcheck_code = 0
                if sig in (0x504D5544, 0x34365544, 0x45474150):  # full dump
                    raw_bc = _struct.unpack_from('<I', header, 0x38)[0]
                    bugcheck_code = raw_bc & 0xFFFF
                elif sig == 0x504D444D:  # minidump
                    num_streams = _struct.unpack_from('<I', header, 0x08)[0]
                    dir_rva = _struct.unpack_from('<I', header, 0x0C)[0]
                    for i in range(min(num_streams, 64)):
                        entry_off = dir_rva + i * 12
                        if entry_off + 12 > dp.stat().st_size:
                            break
                        with open(dp, 'rb') as fh:
                            fh.seek(entry_off)
                            entry = fh.read(12)
                        if len(entry) < 12:
                            break
                        st = _struct.unpack_from('<I', entry, 0)[0]
                        sl = _struct.unpack_from('<I', entry, 4)[0]
                        ss = _struct.unpack_from('<I', entry, 8)[0]
                        if st == 6 and sl > 0:
                            with open(dp, 'rb') as fh:
                                fh.seek(sl)
                                exc_data = fh.read(min(ss, 256))
                            if len(exc_data) >= 4:
                                bugcheck_code = _struct.unpack_from('<I', exc_data, 0)[0] & 0xFFFF
                            break
                if bugcheck_code and 0 < bugcheck_code < 0x600:
                    bc_info = get_bugcheck_info(bugcheck_code)
                    # Each dump file is a separate crash event — don't deduplicate by code
                    mtime = dp.stat().st_mtime
                    dump_bugchecks.append({
                        "code": bc_info['code'],
                        "name": bc_info['name'],
                        "description": bc_info['description'],
                        "file": dp.name,
                        "time": datetime.fromtimestamp(mtime, CHINA_TZ).isoformat(),
                        "source": "Dump文件",
                    })
            except Exception:
                pass

    # Merge dump bugchecks into events list as synthetic Event 1001-style entries
    for dbc in dump_bugchecks:
        restart_events.append({
            "id": 1001,
            "time": dbc["time"],
            "provider": "DumpFile",
            "description": f"BugCheck 蓝屏（转储: {dbc['file']}）",
            "source": "DumpFile",
            "file": dbc["file"],
            "bugcheck_code": int(dbc["code"], 16),
            "bugcheck": {"code": dbc["code"], "name": dbc["name"], "description": dbc["description"]},
        })

    # ═══ Reconstruct restart timeline ───
    # Sort all restart events by time (newest first)
    restart_events.sort(key=lambda x: x.get('time', ''), reverse=True)

    # Classify restart sequences
    shutdowns = [e for e in restart_events if e['id'] in (41, 6008)]
    bugchecks = [e for e in restart_events if e['id'] == 1001]
    normal_restarts = [e for e in restart_events if e['id'] == 1074]
    installs = [e for e in restart_events if e['id'] in (19, 7045)]

    # Assess severity
    unexpected_count = sum(1 for e in restart_events if e['id'] == 41)
    bc_count = len(bugchecks)
    hw_err_count = len(hardware_errors)
    lke_count = len(lke_events)

    if bc_count > 0 or hw_err_count > 5:
        severity = "critical"
    elif unexpected_count > 1 or lke_count > 0 or hw_err_count > 0:
        severity = "warning"
    else:
        severity = "normal"

    findings = []
    diagnostics = []
    if bc_count > 0:
        bc_names = set(bc.get('bugcheck', {}).get('name', '?') for bc in bugchecks if bc.get('bugcheck'))
        findings.append(f"💾 {bc_count} 次蓝屏 → {', '.join(bc_names)}")
        diagnostics.append(("critical", "蓝屏", f"共 {bc_count} 次 BugCheck，代码: {', '.join(bc_names)}"))
    if unexpected_count > 0:
        findings.append(f"⚡ {unexpected_count} 次意外断电 (Event 41)")
        diagnostics.append(("warning", "意外断电", f"共 {unexpected_count} 次 Kernel-Power 事件"))
    if hw_err_count > 0:
        findings.append(f"🔧 {hw_err_count} 条硬件告警记录")
        diagnostics.append(("warning", "硬件告警", f"磁盘/WHEA/驱动等 {hw_err_count} 条告警"))
    if lke_count > 0:
        lke_codes = set(le['code'] for le in lke_events)
        findings.append(f"📝 {lke_count} 个 LiveKernelEvent → {', '.join(lke_codes)}")
        diagnostics.append(("warning", "LiveKernelEvent", f"{lke_count} 个内核硬件事件"))
    if correlated:
        findings.append(f"⚠️ {len(correlated)} 次崩溃前有安装/服务变更记录")
        diagnostics.append(("critical", "安装后崩溃", f"{len(correlated)} 次崩溃紧随服务/更新安装"))

    # ── Event distribution top ──
    syst_top = sorted(syst_dist.items(), key=lambda x: x[1], reverse=True)[:20]
    app_top = sorted(app_dist.items(), key=lambda x: x[1], reverse=True)[:20]

    # ── Build result ──
    result = {
        "title": "📋 系统诊断 — 微软官方诊断标准",
        "severity": severity,
        "findings": findings,
        "diagnostics": diagnostics,
        "reference": "https://learn.microsoft.com/zh-cn/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs",

        # Hardware section
        "hardware_errors": hardware_errors,
        "hardware_error_count": hw_err_count,
        "hw_by_type": {str(k): len(v) for k, v in sorted(hw_by_type.items())},
        "hw_error_types": len(hw_by_type),

        # Restart timeline
        "unexpected_shutdowns_count": unexpected_count,
        "bugcheck_count": bc_count,
        "normal_restart_count": len(normal_restarts),
        "restart_events": restart_events,  # full timeline
        "shutdowns": sorted(shutdowns, key=lambda x: x.get('time', ''), reverse=True),
        "bugchecks": sorted(bugchecks, key=lambda x: x.get('time', ''), reverse=True),

        # Correlated installs → crashes
        "correlated": correlated,
        "correlated_count": len(correlated),

        # LiveKernelEvent
        "lke_events": lke_events,
        "lke_count": lke_count,

        # Event distribution
        "syst_dist": dict(syst_top),
        "syst_total": syst_total,
        "app_dist": dict(app_top),
        "app_total": app_total,

        # Summary
        "summary": f"System.evtx {syst_total} 条记录, Application.evtx {app_total} 条记录 | "
                   f"蓝屏 {bc_count} 次, 意外断电 {unexpected_count} 次, 硬件告警 {hw_err_count} 条, "
                   f"关联安装变更 {len(correlated)} 组",
    }

    return result


# ─── Bug Check Code Reference ──────────────────────────────
# From Microsoft Windows SDK & Debugging Tools documentation
BUGCHECK_MAP = {
    0x00000001: ("APC_INDEX_MISMATCH", "内核 APC 索引不匹配"),
    0x0000000A: ("IRQL_NOT_LESS_OR_EQUAL", "驱动在过高 IRQL 访问分页内存"),
    0x0000000D: ("MUTEX_LEVEL_NUMBER_VIOLATION", "互斥锁层级违规"),
    0x00000019: ("BAD_POOL_HEADER", "内存池头损坏，通常由驱动错误引起"),
    0x0000001A: ("MEMORY_MANAGEMENT", "内存管理严重错误，可能是 RAM 故障"),
    0x0000001E: ("KMODE_EXCEPTION_NOT_HANDLED", "内核模式异常未被处理"),
    0x00000024: ("NTFS_FILE_SYSTEM", "NTFS 文件系统错误，磁盘可能损坏"),
    0x0000002E: ("DATA_BUS_ERROR", "数据总线错误，硬件内存故障"),
    0x0000003B: ("SYSTEM_SERVICE_EXCEPTION", "系统服务异常，通常由驱动引起"),
    0x0000003D: ("INTERRUPT_EXCEPTION_NOT_HANDLED", "中断异常未处理"),
    0x00000041: ("MUST_SUCCEED_POOL_EMPTY", "必须成功的池分配失败"),
    0x00000044: ("MULTIPLE_IRP_COMPLETE_REQUESTS", "驱动重复完成 IRP"),
    0x0000004E: ("PFN_LIST_CORRUPT", "页帧号列表损坏，通常 RAM 问题"),
    0x00000050: ("PAGE_FAULT_IN_NONPAGED_AREA", "引用无效内存，驱动或 RAM 故障"),
    0x00000051: ("REGISTRY_ERROR", "注册表错误"),
    0x00000058: ("FTDISK_INTERNAL_ERROR", "磁盘容错驱动内部错误"),
    0x0000005A: ("CRITICAL_SERVICE_FAILED", "关键系统服务启动失败"),
    0x0000005C: ("HAL_INITIALIZATION_FAILED", "硬件抽象层初始化失败"),
    0x00000074: ("BAD_SYSTEM_CONFIG_INFO", "系统配置信息损坏"),
    0x00000077: ("KERNEL_STACK_INPAGE_ERROR", "内核栈从磁盘交换页面失败"),
    0x0000007A: ("KERNEL_DATA_INPAGE_ERROR", "内核数据页面读取失败，磁盘/内存问题"),
    0x0000007B: ("INACCESSIBLE_BOOT_DEVICE", "无法访问启动设备"),
    0x0000007E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "系统线程异常未处理"),
    0x0000007F: ("UNEXPECTED_KERNEL_MODE_TRAP", "意外内核模式陷阱，通常硬件/CPU"),
    0x0000008E: ("KERNEL_MODE_EXCEPTION_NOT_HANDLED", "内核模式异常，驱动引发"),
    0x0000009C: ("MACHINE_CHECK_EXCEPTION", "CPU 检测到不可恢复硬件错误"),
    0x0000009F: ("DRIVER_POWER_STATE_FAILURE", "驱动电源状态转换失败。常见原因：网卡/存储/显卡驱动在睡眠唤醒时无响应"),
    0x000000A0: ("INTERNAL_POWER_ERROR", "内部电源管理错误"),
    0x000000A5: ("ACPI_BIOS_ERROR", "ACPI BIOS 不兼容或损坏"),
    0x000000BE: ("ATTEMPTED_WRITE_TO_READONLY_MEMORY", "尝试写入只读内存"),
    0x000000C1: ("SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION", "特殊池检测到内存损坏"),
    0x000000C2: ("BAD_POOL_CALLER", "当前线程发出了错误的池请求"),
    0x000000C4: ("DRIVER_VERIFIER_DETECTED_VIOLATION", "Driver Verifier 检测到违规"),
    0x000000C5: ("DRIVER_CORRUPTED_EXPOOL", "驱动损坏了系统池"),
    0x000000C9: ("DRIVER_VERIFIER_IOMANAGER_VIOLATION", "Driver Verifier I/O 违规"),
    0x000000CE: ("DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS", "驱动卸载时未取消待处理操作"),
    0x000000D1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "驱动在过高 IRQL 访问分页内存（最常见）"),
    0x000000D2: ("BUGCODE_ID_DRIVER", "ID 驱动错误"),
    0x000000D5: ("DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL", "驱动访问已释放的特殊池"),
    0x000000D6: ("DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION", "驱动访问超出分配"),
    0x000000D8: ("DRIVER_USED_EXCESSIVE_PTES", "驱动使用过多页表项"),
    0x000000DA: ("SYSTEM_PTE_MISUSE", "系统页表项误用"),
    0x000000E2: ("MANUALLY_INITIATED_CRASH", "人工触发的崩溃（键盘 Ctrl+ScrollLock 等）"),
    0x000000E3: ("RESOURCE_NOT_OWNED", "线程释放不拥有的资源"),
    0x000000EA: ("THREAD_STUCK_IN_DEVICE_DRIVER", "线程卡在设备驱动中，通常显卡驱动"),
    0x000000EF: ("CRITICAL_PROCESS_DIED", "关键系统进程意外终止"),
    0x000000F4: ("CRITICAL_OBJECT_TERMINATION", "关键系统对象意外终止"),
    0x000000F7: ("DRIVER_OVERRAN_STACK_BUFFER", "驱动栈缓冲区溢出"),
    0x000000FC: ("ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY", "尝试执行不可执行内存"),
    0x000000FD: ("DIRTY_NOWRITE_PAGES_CONGESTION", "脏页面累积"),
    0x000000FE: ("BUGCODE_USB_DRIVER", "USB 驱动错误"),
    0x00000101: ("CLOCK_WATCHDOG_TIMEOUT", "时钟中断超时，处理器无响应"),
    0x00000104: ("AGP_INVALID_ACCESS", "AGP 无效访问"),
    0x00000109: ("CRITICAL_STRUCTURE_CORRUPTION", "内核关键数据结构损坏"),
    0x0000010E: ("VIDEO_MEMORY_MANAGEMENT_INTERNAL", "显存管理内部错误"),
    0x00000113: ("VIDEO_DXGKRNL_FATAL_ERROR", "显卡内核严重错误"),
    0x00000116: ("VIDEO_TDR_FAILURE", "显卡超时检测恢复失败"),
    0x00000117: ("VIDEO_TDR_TIMEOUT_DETECTED", "显卡超时，驱动无响应"),
    0x00000119: ("VIDEO_SCHEDULER_INTERNAL_ERROR", "显卡调度器内部错误"),
    0x0000011B: ("DRIVER_RETURNED_HOLDING_CANCEL_LOCK", "驱动返回时持有取消锁"),
    0x00000122: ("WHEA_INTERNAL_ERROR", "Windows 硬件错误架构内部错误"),
    0x00000124: ("WHEA_UNCORRECTABLE_ERROR", "硬件不可纠正错误（CPU/PCIe/内存）"),
    0x0000012B: ("FAULTY_HARDWARE_CORRUPTED_PAGE", "硬件损坏页面，通常内存故障"),
    0x00000133: ("DPC_WATCHDOG_VIOLATION", "DPC 超时，驱动/固件/SSD 常见"),
    0x00000139: ("KERNEL_SECURITY_CHECK_FAILURE", "内核安全检查失败"),
    0x0000013A: ("KERNEL_MODE_HEAP_CORRUPTION", "内核模式堆损坏"),
    0x00000141: ("VIDEO_ENGINE_TIMEOUT_DETECTED", "显卡引擎超时"),
    0x00000144: ("BUGCODE_USB3_DRIVER", "USB3 驱动错误"),
    0x00000154: ("UNEXPECTED_STORE_EXCEPTION", "存储组件意外异常"),
    0x00000157: ("KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION", "内核线程优先级违规"),
    0x0000018B: ("SECURE_KERNEL_ERROR", "安全内核错误"),
    0x000001C4: ("DRIVER_VERIFIER_DETECTED_VIOLATION_LIVEDUMP", "Driver Verifier 实时转储"),
    0x000001C5: ("IO_DRIVER_INVALID_DEVICE_REQUEST", "I/O 驱动无效设备请求"),
    0x000003FE: ("BUGCODE_USB_DRIVER_LIVEDUMP", "USB 驱动实时转储"),
}

def get_bugcheck_info(code: int) -> dict:
    """Return human-readable info for a bug check code."""
    if code in BUGCHECK_MAP:
        name, desc = BUGCHECK_MAP[code]
        return {"code": f"0x{code:08X}", "name": name, "description": desc}
    else:
        return {"code": f"0x{code:08X}", "name": f"BUGCHECK_{code:X}", "description": "未知错误代码"}


def parse_single_dump(filepath: Path, log_dir: Path = None) -> dict:
    """Parse a single .dmp file and extract BugCheck info.
    
    Args:
        filepath: Path to the .dmp file
        log_dir: Optional path to the log directory (for evtx cross-reference)
    
    Returns dict with bugcheck code, name, description, params, dump type, drivers,
    and optionally event_1001 cross-reference data.
    """
    import struct, re
    info = {
        "filename": filepath.name,
        "size": filepath.stat().st_size,
        "size_kb": round(filepath.stat().st_size / 1024, 1),
        "size_mb": round(filepath.stat().st_size / 1048576, 1),
    }

    try:
        with open(filepath, 'rb') as fh:
            header = fh.read(0x200)
        if len(header) < 4:
            info["error"] = "文件太小，不是有效的转储文件"
            return info

        sig = struct.unpack_from('<I', header, 0)[0]
        is_minidump = (sig == 0x504D444D)  # 'MDMP'
        is_full_dump = (sig in (0x504D5544, 0x34365544, 0x45474150))  # 'DUMP', 'DU64', 'PAGE'

        if is_full_dump:
            info['dump_type'] = '完整内存转储 (Kernel/Full)'
        elif is_minidump:
            info['dump_type'] = '微型转储 (Minidump)'
        else:
            info['dump_type'] = f'未知格式 (signature: 0x{sig:08X})'

        bugcheck_code = 0
        bugcheck_params = []

        if is_full_dump:
            raw_bc = struct.unpack_from('<I', header, 0x38)[0]
            bugcheck_code = raw_bc & 0xFFFF
            bugcheck_params = [
                struct.unpack_from('<Q', header, off)[0]
                for off in [0x40, 0x48, 0x50, 0x58]
            ]
        elif is_minidump:
            num_streams = struct.unpack_from('<I', header, 0x08)[0]
            dir_rva = struct.unpack_from('<I', header, 0x0C)[0]
            size = filepath.stat().st_size
            for i in range(min(num_streams, 64)):
                entry_off = dir_rva + i * 12
                if entry_off + 12 > size:
                    break
                with open(filepath, 'rb') as fh:
                    fh.seek(entry_off)
                    entry = fh.read(12)
                if len(entry) < 12:
                    break
                stream_type = struct.unpack_from('<I', entry, 0)[0]
                stream_loc = struct.unpack_from('<I', entry, 4)[0]
                stream_size = struct.unpack_from('<I', entry, 8)[0]
                if stream_type == 6 and stream_loc > 0:
                    with open(filepath, 'rb') as fh:
                        fh.seek(stream_loc)
                        exc_data = fh.read(min(stream_size, 256))
                    if len(exc_data) >= 4:
                        bugcheck_code = struct.unpack_from('<I', exc_data, 0)[0] & 0xFFFF
                        if len(exc_data) >= 40:
                            num_params = struct.unpack_from('<I', exc_data, 20)[0]
                            bugcheck_params = [
                                struct.unpack_from('<I', exc_data, 24 + j * 4)[0]
                                for j in range(min(num_params, 4))
                            ]
                    break

        if bugcheck_code and 0 < bugcheck_code < 0x600:
            info['bugcheck'] = get_bugcheck_info(bugcheck_code)
            if bugcheck_params:
                info['bugcheck_params'] = [f"0x{p:X}" for p in bugcheck_params]
        elif bugcheck_code:
            info['bugcheck_raw'] = f"0x{bugcheck_code:08X}"
            if bugcheck_params:
                info['bugcheck_params'] = [f"0x{p:X}" for p in bugcheck_params]

        # Extract driver names (sample for large files)
        # NOTE: Full kernel dumps (DUMP/DU64/PAGE) do NOT contain plaintext
        # driver paths like minidumps do. Driver info is in kernel structures
        # that require WinDbg-level parsing. We do a best-effort scan.
        MS_PREFIXES = {'ntoskrnl', 'hal', 'ntdll', 'win32k', 'dxgkrnl', 'dxgmms',
                       'storport', 'stornvme', 'ndis', 'tcpip', 'afd', 'netio',
                       'fltmgr', 'clipsp', 'ksecdd', 'cng', 'msrpc', 'volmgr',
                       'volsnap', 'disk', 'partmgr', 'acpi', 'pci', 'usb',
                       'hid', 'i8042prt', 'kbdclass', 'mouclass', 'usbhub',
                       'usbehci', 'usbxhci', 'vhf', 'wdf', 'wmilib', 'watchdog',
                       'spaceport', 'fvevol', 'rdyboost', 'mup', 'dfsc', 'wof',
                       'filecrypt', 'fileinfo', 'clfs', 'ntfs', 'fastfat',
                       'mountmgr', 'msfs', 'npfs', 'fs_rec', 'cdfs', 'udfs',
                       'wfplwfs', 'mslldp', 'lltdio', 'rspndr', 'wanarp',
                       'pacer', 'tdx', 'netbios', 'nwifi', 'vwifibus', 'vwififlt',
                       'msiscsi', 'sbp2port', 'cdrom', 'usbstor', 'uaspstor'}
        drivers = set()
        third_party = set()
        file_size = filepath.stat().st_size
        if file_size < 10 * 1024 * 1024:
            with open(filepath, 'rb') as fh:
                data = fh.read()
            for m in re.finditer(rb'[a-zA-Z0-9_\\-]+\\[a-zA-Z0-9_]+\\.sys', data):
                drv = m.group().decode('ascii', errors='replace')
                name = drv.split('\\')[-1].lower().replace('.sys', '')
                drivers.add(name)
                if name not in MS_PREFIXES and not name.startswith(('ms', 'windows', 'microsoft')):
                    third_party.add(name)
        else:
            drv_re = re.compile(rb'[a-zA-Z0-9_\\-]+\\[a-zA-Z0-9_]+\\.sys')
            for offset in range(0, file_size, 16 * 1024 * 1024):
                with open(filepath, 'rb') as fh:
                    fh.seek(offset)
                    chunk = fh.read(0x10000)
                for m in drv_re.finditer(chunk):
                    drv = m.group().decode('ascii', errors='replace')
                    name = drv.split('\\')[-1].lower().replace('.sys', '')
                    drivers.add(name)
                    if name not in MS_PREFIXES and not name.startswith(('ms', 'windows', 'microsoft')):
                        third_party.add(name)
        if drivers:
            info['drivers'] = sorted(drivers)[:30]
        if third_party:
            info['third_party_drivers'] = sorted(third_party)
        info['driver_count'] = len(drivers)
        info['third_party_count'] = len(third_party)

        # For full dumps: driver extraction is very limited
        if is_full_dump:
            if not drivers:
                info['driver_note'] = ("⚠️ 这是完整内存转储，不含明文驱动模块列表。"
                                       "【重要】其他 dump 文件也是同样类型，解析它们不会得到驱动信息。"
                                       "请改用 read_evtx_events 查询 System.evtx 获取驱动相关事件。")
            else:
                info['driver_note'] = ("⚠️ 完整内存转储驱动提取有限。"
                                       "以上仅来自二进制扫描中偶然出现的 .sys 字符串，不完整。"
                                       "如需完整列表，请用 read_evtx_events 查询事件日志。")

        # ── Cross-reference with System.evtx Event 1001 ──
        if log_dir and bugcheck_code and 0 < bugcheck_code < 0x600:
            evtx_path = log_dir / "oslog" / "System.evtx"
            if evtx_path.exists():
                try:
                    from Evtx.Evtx import Evtx
                    from lxml import etree
                    NS_CROSS = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                    matched_events = []
                    with Evtx(str(evtx_path)) as evtx_log:
                        for record in evtx_log.records():
                            try:
                                root = etree.fromstring(record.xml())
                            except Exception:
                                continue
                            eid_el = root.find('.//ns:EventID', NS_CROSS)
                            if eid_el is None or int(eid_el.text or '0') != 1001:
                                continue
                            # Extract Data fields
                            evt_data = {}
                            for d in root.findall('.//ns:Data', NS_CROSS):
                                name = d.get('Name', '')
                                text = (d.text or '').strip()
                                if text:
                                    evt_data[name] = text
                            # Match by BugCheck code
                            bc_match = None
                            for key in ['BugcheckCode', 'param1']:
                                val = evt_data.get(key, '')
                                if val.startswith('0x'):
                                    try:
                                        if int(val.split()[0], 16) == bugcheck_code:
                                            bc_match = True
                                            break
                                    except ValueError:
                                        pass
                            if bc_match:
                                ts_el = root.find('.//ns:TimeCreated', NS_CROSS)
                                evt = {'time': ts_el.get('SystemTime', '') if ts_el is not None else ''}
                                # Extract driver/image info
                                for key, label in [('param1', 'param1'), ('param2', 'dump_path'),
                                                   ('param3', 'guid'), ('BugcheckCode', 'BugcheckCode'),
                                                   ('BugcheckParameter1', 'BugcheckParameter1'),
                                                   ('BugcheckParameter2', 'BugcheckParameter2'),
                                                   ('BugcheckParameter3', 'BugcheckParameter3'),
                                                   ('BugcheckParameter4', 'BugcheckParameter4'),
                                                   ('DriverName', 'DriverName'),
                                                   ('ImageName', 'ImageName'),
                                                   ('Image name', 'Image name')]:
                                    if key in evt_data:
                                        evt[label or key] = evt_data[key]
                                matched_events.append(evt)
                                if len(matched_events) >= 3:
                                    break
                    if matched_events:
                        info['event_1001'] = matched_events
                except Exception:
                    pass  # evtx cross-reference is best-effort

    except Exception as e:
        info['error'] = f"解析失败: {str(e)[:200]}"

    return info


def analyze_dump(tslog: Path) -> dict:
    """💾 详细 Dump 分析：二进制解析 + Event 1001 交叉关联"""
    import re, struct
    dump_dir = tslog / "osdump"
    if not dump_dir.is_dir():
        return {"title": "💾 Dump 分析", "dumps": {},
                "message": "当前日志包中未包含 Dump 文件。请将 C:\\Windows\\Minidump\\ 下的 .dmp 文件打包上传。"}

    # Check if there are actual .dmp files before scanning evtx
    dmp_files = [f for f in dump_dir.iterdir() if f.suffix.lower() == '.dmp' and f.stat().st_size > 0]
    if not dmp_files:
        return {"title": "💾 Dump 分析", "dumps": {},
                "total_dumps": 0,
                "message": "osdump 文件夹为空或无有效转储文件。请将 C:\\Windows\\Minidump\\ 下的 .dmp 文件打包上传。"}

    # ── Step 1: Parse System.evtx Event 1001 (BugCheck) for context ──
    # Limit scan to keep it fast
    evtx_dir = tslog / "oslog"
    bugcheck_events = []
    if evtx_dir.is_dir():
        system_evtx = evtx_dir / "System.evtx"
        if system_evtx.exists():
            for eid, lvl, ts, prov, root in iter_evtx(system_evtx, max_events=2000):
                if eid != 1001:
                    continue
                evt = {"time": ts, "provider": prov}
                # Extract BugCheckCode and params from Data elements
                data_items = root.findall('.//{http://schemas.microsoft.com/win/2004/08/events/event}Data')
                for d in data_items:
                    name = d.get('Name', '')
                    text = (d.text or '').strip()
                    if not text:
                        continue
                    if name == 'BugcheckCode':
                        try:
                            evt['bugcheck_code'] = int(text)
                            evt['bugcheck'] = get_bugcheck_info(int(text))
                        except ValueError:
                            evt['bugcheck_code'] = 0
                    elif name == 'BugcheckParameter1':
                        evt['param1'] = text
                    elif name == 'BugcheckParameter2':
                        evt['param2'] = text
                    elif name == 'BugcheckParameter3':
                        evt['param3'] = text
                    elif name == 'BugcheckParameter4':
                        evt['param4'] = text
                    elif name == 'SleepInProgress':
                        evt['sleep_in_progress'] = text == 'true'
                    elif name == 'PowerButtonTimestamp':
                        evt['power_button_ts'] = text
                if evt.get('bugcheck_code'):
                    bugcheck_events.append(evt)

    # ── Step 2: Parse each dump file ──
    dumps = {}
    for f in sorted(dmp_files):
        size = f.stat().st_size
        mtime = f.stat().st_mtime
        info = {
            "filename": f.name, "size": size,
            "size_kb": round(size / 1024, 1),
            "size_mb": round(size / 1048576, 1),
            "mtime": datetime.fromtimestamp(mtime, CHINA_TZ).isoformat(),
        }

        try:
            with open(f, 'rb') as fh:
                header = fh.read(0x200)

            sig = struct.unpack_from('<I', header, 0)[0] if len(header) >= 4 else 0
            is_minidump = (sig == 0x504D444D)  # 'MDMP'
            is_full_dump = (sig in (0x504D5544, 0x34365544, 0x45474150))  # 'DUMP', 'DU64', 'PAGE'

            if is_full_dump:
                info['dump_type'] = '完整内存转储 (Kernel/Full)'
            elif is_minidump:
                info['dump_type'] = '微型转储 (Minidump)'
            else:
                info['dump_type'] = f'未知格式 (signature: 0x{sig:08X})'

            # ── Bug Check Code extraction ──
            bugcheck_code = 0
            bugcheck_params = []

            if is_full_dump:
                # DUMP_HEADER64 / PAGE_HEADER: BugCheckCode at offset 0x38
                # BugCheckCode may have high bits set (e.g. 0x1000009F → actual 0x9F)
                raw_bc = struct.unpack_from('<I', header, 0x38)[0]
                bugcheck_code = raw_bc & 0xFFFF  # Strip high bits
                # BugCheckParameter1-4 are ULONG64 at offsets 0x40, 0x48, 0x50, 0x58
                bugcheck_params = [
                    struct.unpack_from('<Q', header, off)[0]
                    for off in [0x40, 0x48, 0x50, 0x58]
                ]
            elif is_minidump:
                # MINIDUMP_HEADER: followed by stream directory
                # Parse stream directory to find Exception stream
                num_streams = struct.unpack_from('<I', header, 0x08)[0]
                dir_rva = struct.unpack_from('<I', header, 0x0C)[0]
                # Stream directory entries: StreamType(4) + Location(4+4)
                stream_dir_off = dir_rva  # RVA relative to start of file
                for i in range(min(num_streams, 64)):
                    entry_off = stream_dir_off + i * 12
                    if entry_off + 12 > size:
                        break
                    # Read stream entry
                    with open(f, 'rb') as fh:
                        fh.seek(entry_off)
                        entry = fh.read(12)
                    if len(entry) < 12:
                        break
                    stream_type = struct.unpack_from('<I', entry, 0)[0]
                    stream_loc = struct.unpack_from('<I', entry, 4)[0]
                    stream_size = struct.unpack_from('<I', entry, 8)[0]
                    if stream_type == 6 and stream_loc > 0:  # ExceptionStream
                        with open(f, 'rb') as fh:
                            fh.seek(stream_loc)
                            exc_data = fh.read(min(stream_size, 256))
                        if len(exc_data) >= 4:
                            bugcheck_code = struct.unpack_from('<I', exc_data, 0)[0]
                            bugcheck_code = bugcheck_code & 0xFFFF  # Strip high bits
                            # Exception params follow at offset 24 (after 16 bytes header + 4+4 alignment)
                            if len(exc_data) >= 40:
                                num_params = struct.unpack_from('<I', exc_data, 20)[0]
                                bugcheck_params = [
                                    struct.unpack_from('<I', exc_data, 24 + j*4)[0]
                                    for j in range(min(num_params, 4))
                                ]
                        break

            # ── Match with Event 1001 ──
            matched_event = None
            if bugcheck_code and bugcheck_events:
                for evt in bugcheck_events:
                    if evt.get('bugcheck_code') == bugcheck_code:
                        # Check time proximity
                        evt_ts = None
                        try:
                            evt_ts = datetime.fromisoformat(evt['time'].replace('Z', '+00:00'))
                        except Exception:
                            pass
                        dump_ts = datetime.fromtimestamp(mtime, timezone.utc)
                        if evt_ts and abs((dump_ts - evt_ts).total_seconds()) < 86400:
                            matched_event = evt
                            break

            # ── Build result ──
            if bugcheck_code and 0 < bugcheck_code < 0x600:
                info['bugcheck'] = get_bugcheck_info(bugcheck_code)
                if bugcheck_params:
                    info['bugcheck_params'] = [f"0x{p:X}" for p in bugcheck_params]
                if matched_event:
                    info['event_1001'] = matched_event

            # Extract driver names from string table (sample at intervals)
            drivers = set()
            # For small files (<10MB): scan whole file. For large: sample at intervals
            if size < 10 * 1024 * 1024:
                with open(f, 'rb') as fh:
                    data = fh.read()
                for m in re.finditer(rb'[a-zA-Z0-9_\\-]+\\[a-zA-Z0-9_]+\.sys', data):
                    drv = m.group().decode('ascii', errors='replace')
                    if len(drv) < 80:
                        drivers.add(drv.rsplit('\\', 1)[-1])
            else:
                # Sample at 16MB intervals throughout the file
                drv_re = re.compile(rb'[a-zA-Z0-9_\\-]+\\[a-zA-Z0-9_]+\.sys')
                for offset in range(0, size, 16 * 1024 * 1024):
                    with open(f, 'rb') as fh:
                        fh.seek(offset)
                        chunk = fh.read(0x10000)
                    for m in drv_re.finditer(chunk):
                        drv = m.group().decode('ascii', errors='replace')
                        if len(drv) < 80:
                            drivers.add(drv.rsplit('\\', 1)[-1])
            info['drivers'] = sorted(drivers)[:20]
            info['driver_count'] = len(drivers)

        except Exception as e:
            info['parse_error'] = str(e)

        dumps[f.name] = info

    # ── Summary ──
    total = len(dumps)
    unique_checks = {}
    for d in dumps.values():
        if 'bugcheck' in d:
            code = d['bugcheck']['code']
            if code not in unique_checks:
                unique_checks[code] = d['bugcheck']

    return {
        "title": "💾 Dump 详细分析",
        "dumps": dumps,
        "total_dumps": total,
        "unique_bugchecks": list(unique_checks.values()),
        "bugcheck_events_from_evtx": bugcheck_events,
        "summary": f"共 {total} 个转储文件，{len(unique_checks)} 种不同蓝屏代码" if total > 0 else "未找到 Dump 文件",
    }


def analyze_siolog(tslog: Path) -> dict:
    """📋 SIOlog 分析：解析 Lenovo SIO_Events.log"""
    import re
    siolog_path = tslog / "SIO_Events.log"
    if not siolog_path.exists():
        return {"title": "📋 SIOlog 分析", "found": False,
                "message": "当前日志包中未包含 SIO_Events.log 文件"}

    enc = detect_encoding(siolog_path)
    try:
        with open(siolog_path, 'r', encoding=enc, errors='replace') as f:
            content = f.read()
    except Exception as e:
        return {"title": "📋 SIOlog 分析", "found": True, "error": str(e)}

    # Parse header info
    info = {"found": True, "raw_size": len(content)}
    for field, pattern in [
        ("product_id", r'SIO Product ID = (.+)'),
        ("firmware_version", r'SIO Firmware Version = (.+)'),
        ("event_count", r'Event Num = (\d+)'),
        ("last_event_id", r'LastEventId = (\d+)'),
        ("mtm", r'MTM: (.+)'),
        ("serial", r'SN: (.+)'),
        ("util_version", r'Version ([\d.]+)'),
    ]:
        m = re.search(pattern, content)
        if m:
            info[field] = m.group(1).strip()

    # Parse events: EventNNN: YYYY/MM/DD HH:MM:SS  NXXX XX XX XX XX XX XX
    events = []
    event_codes = set()
    for m in re.finditer(r'Event(\d{3}): (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+(N\d{3})\s+([0-9A-Fa-f ]+)', content):
        idx, ts, code, data = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        events.append({"index": int(idx), "time": ts, "code": code, "data": data})
        event_codes.add(code)

    # Non-N000 events = potential issues
    issue_events = [e for e in events if e['code'] != 'N000']
    boot_events = [e for e in events if e['code'] == 'N000']

    return {
        "title": "📋 SIOlog 分析 — Lenovo SIO/EC 事件日志",
        "found": True,
        "header": info,
        "total_events": len(events),
        "unique_codes": sorted(event_codes),
        "boot_count": len(boot_events),
        "issue_events": issue_events,
        "issue_count": len(issue_events),
        "all_events": events[-200:],  # Last 200 events
        "summary": f"共 {len(events)} 个事件，{len(boot_events)} 次启动记录，{len(issue_events)} 个异常事件" if events else "无事件记录",
    }


def analyze_summary(tslog: Path) -> dict:
    """📊 整体分析总结：汇总所有分析结果（优先使用已缓存报告）"""
    results = {}
    findings = []
    severity = "normal"

    # First try to load from existing report files
    # We need the job_id - search reports dir for files matching this tslog's parent
    import re
    job_id = None
    for rp in REPORT_DIR.glob("*_overview.json"):
        jid = rp.stem.replace("_overview", "")
        # Check if this job's tslog matches
        if jid in jobs and jobs[jid].get("tslog_path") == str(tslog):
            job_id = jid
            break

    for atype in _STANDARD_TYPES:
        try:
            # Try cached report first
            if job_id:
                cached = REPORT_DIR / f"{job_id}_{atype}.json"
                if cached.exists():
                    with open(cached, 'r', encoding='utf-8') as f:
                        results[atype] = json.load(f)
                    continue
            # Fall back to live analysis
            analyzer = ANALYZERS.get(atype)
            if analyzer:
                results[atype] = analyzer(tslog)
        except Exception as e:
            results[atype] = {"error": str(e)}

    # Extract key findings

    # System diagnostics (combined reboot + hardware + events)
    diag = results.get("diagnostics", {})
    power_loss = diag.get("unexpected_shutdowns_count", 0)
    bc_count = diag.get("bugcheck_count", 0)
    hw_errs = diag.get("hardware_error_count", 0)
    lke_count = diag.get("lke_count", 0)
    correlated = diag.get("correlated_count", 0)

    if bc_count > 0:
        findings.append(f"💾 {bc_count} 次蓝屏")
        severity = "critical"
    if power_loss > 0:
        findings.append(f"⚡ {power_loss} 次意外断电 (Event 41)")
        if severity != "critical":
            severity = "critical" if power_loss > 5 else ("warning" if power_loss > 1 else severity)
    if hw_errs > 0:
        findings.append(f"🔧 {hw_errs} 条硬件告警")
        if severity not in ("critical",):
            severity = "warning"
    if lke_count > 0:
        findings.append(f"📝 {lke_count} 个 LiveKernelEvent")
        if severity not in ("critical",):
            severity = "warning"
    if correlated > 0:
        findings.append(f"⚠️ {correlated} 次崩溃前有安装/服务变更")

    # Dump analysis
    dump = results.get("dump", {})
    dumps_found = dump.get("total_dumps", 0)
    unique_bc = dump.get("unique_bugchecks", [])
    if dumps_found > 0:
        bc_names = [bc.get('name', '?') for bc in unique_bc]
        findings.append(f"💾 {dumps_found} 个转储文件 → {', '.join(bc_names)}")
        severity = "critical"

    # SIOlog
    sio = results.get("siolog", {})
    if sio.get("found"):
        sio_issues = sio.get("issue_count", 0)
        if sio_issues > 0:
            findings.append(f"📋 SIOlog {sio_issues} 个异常事件")

    if not findings:
        findings.append("✅ 未发现明显异常")
        severity = "ok"

    return {
        "title": "📊 整体分析总结",
        "severity": severity,
        "findings": findings,
        "power_loss_count": power_loss,
        "dump_count": dumps_found,
        "lke_count": lke_count,
        "detail": {k: {"title": v.get("title", k), "summary": v.get("summary", "")} for k, v in results.items()},
    }


# ─── Linux Analysis Functions ────────────────────────────────

def analyze_linux_overview(log_dir: Path) -> dict:
    """📄 Linux 系统概览：提取 OS/内核/硬件信息"""
    import re

    def read_first(path: str, max_kb: int = 50) -> str:
        fp = log_dir / path
        if not fp.exists():
            for alt in log_dir.rglob(path):
                fp = alt; break
        if not fp.exists():
            return ""
        size = fp.stat().st_size
        with open(fp, 'r', encoding='utf-8', errors='replace') as f:
            return f.read(min(size, max_kb * 1024))

    def find_read(pattern: str, max_kb: int = 50) -> str:
        for fname in log_dir.rglob(pattern.replace('*', '*')):
            if fname.is_file():
                return read_first(str(fname.relative_to(log_dir)), max_kb)
        return ""

    # OS info
    os_info = {}
    release = find_read('*os-release*') or find_read('*lsb-release*')
    if release:
        for line in release.split('\n'):
            if '=' in line:
                k, v = line.strip().split('=', 1)
                os_info[k.lower()] = v.strip("'").strip('"')

    # Kernel version
    kernel_ver = find_read('proc/version*', 5) or read_first('dmesg', 2)
    if kernel_ver:
        m = re.search(r'Linux version ([\S]+)', kernel_ver)
        if m:
            os_info['kernel'] = m.group(1)

    # Hostname
    hostname = find_read('*hostname*', 2) or find_read('proc/sys/kernel/hostname*', 1)
    if hostname:
        os_info['hostname'] = hostname.strip()

    # Uptime
    uptime = find_read('proc/uptime*', 1)
    if uptime:
        parts = uptime.strip().split()
        if parts:
            try:
                secs = float(parts[0])
                days = int(secs // 86400)
                hours = int((secs % 86400) // 3600)
                os_info['uptime'] = f"{days}天{hours}小时" if days > 0 else f"{int(secs/3600)}小时"
            except:
                os_info['uptime'] = uptime.strip()

    # CPU info
    cpu_info = find_read('proc/cpuinfo*', 20) or read_first('cpuinfo', 10)
    cpu_model = ""
    cpu_cores = 0
    if cpu_info:
        for line in cpu_info.split('\n'):
            if 'model name' in line:
                cpu_model = line.split(':', 1)[1].strip()
                break
        cpu_cores = len([l for l in cpu_info.split('\n') if 'processor' in l])

    # Memory info
    mem = {}
    mem_info = find_read('proc/meminfo*', 10) or read_first('meminfo', 10)
    if mem_info:
        for key in ['MemTotal', 'MemAvailable', 'SwapTotal']:
            m = re.search(rf'{key}:\s+(\d+)', mem_info)
            if m:
                mem[key] = f"{int(m.group(1)) // 1024} MB"

    # Disk info
    disks = []
    df_output = find_read('*df*', 10) or read_first('disk-usage', 5)
    mounts_info = find_read('proc/mounts*', 10) or read_first('fstab', 10)

    # Files in directory
    file_list = {}
    for f in sorted(log_dir.rglob('*')):
        if f.is_file():
            rel = str(f.relative_to(log_dir))
            size_kb = round(f.stat().st_size / 1024, 1)
            file_list[rel] = {"size": f.stat().st_size, "kb": size_kb}

    return {
        "title": "📄 Linux 系统概览",
        "os_info": os_info,
        "cpu": cpu_model,
        "cpu_cores": cpu_cores,
        "memory": mem,
        "disks": disks,
        "files": file_list,
        "file_count": len(file_list),
        "summary": f"{os_info.get('pretty_name', os_info.get('name', 'Linux'))} | 内核 {os_info.get('kernel', '?')} | {cpu_model or '?'}",
    }


def analyze_linux_kernel(log_dir: Path) -> dict:
    """🔧 Linux 内核诊断：OOM killer / kernel panic / 硬件错误"""
    import re

    def read_log(pattern: str, max_mb: int = 2) -> str:
        for f in log_dir.rglob('*'):
            if pattern.lower() in f.name.lower() and f.is_file():
                size = f.stat().st_size
                with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                    return fh.read(min(size, max_mb * 1024 * 1024))
        return ""

    kern_text = read_log('kern') or read_log('dmesg')

    findings = []
    severity = "ok"

    # OOM killer
    oom_events = re.findall(r'(\S+\s+\d+\s+\d+:\d+:\d+).*?(?:oom|Out of memory|invoked oom-killer)', kern_text, re.IGNORECASE)
    if oom_events:
        findings.append(f"🔴 OOM Killer 被触发 {len(oom_events)} 次")
        severity = "critical"

    # Kernel panic / oops
    panics = re.findall(r'(Kernel panic|BUG:|general protection fault)', kern_text, re.IGNORECASE)
    if panics:
        findings.append(f"🔴 内核严重错误 {len(panics)} 次")
        severity = "critical"

    # Hardware errors (MCE, PCIe, ATA errors)
    hw_errs = []
    for pattern in [r'Hardware Error', r'machine check exception', r'PCIe.*error', r'ATA.*error',
                     r'sector.*error', r'I/O error', r'link down']:
        matches = re.findall(pattern, kern_text, re.IGNORECASE)
        if matches:
            hw_errs.extend(matches)
    if hw_errs:
        findings.append(f"🔧 硬件/磁盘错误 {len(hw_errs)} 条")
        if severity == "ok":
            severity = "warning"

    # Segmentation faults
    segfaults = re.findall(r'segfault at', kern_text, re.IGNORECASE)
    if segfaults:
        findings.append(f"⚠️ 段错误 (segfault) {len(segfaults)} 次")

    # Extract key timeline events
    timeline = []
    for m in re.finditer(r'(\w+\s+\d+\s+\d+:\d+:\d+).*(?:panic|oops|OOM|error|fail|BUG)', kern_text, re.IGNORECASE):
        timeline.append(m.group(0)[:200])

    if not findings:
        findings.append("✅ 内核日志未发现异常")

    return {
        "title": "🔧 Linux 内核诊断",
        "severity": severity,
        "findings": findings,
        "oom_count": len(oom_events),
        "panic_count": len(panics),
        "hw_error_count": len(hw_errs),
        "segfault_count": len(segfaults),
        "timeline": timeline[:30],
        "summary": f"{len(oom_events)}次OOM / {len(panics)}次严重错误 / {len(hw_errs)}条硬件异常",
    }


def analyze_linux_syslog(log_dir: Path) -> dict:
    """📋 Linux 系统日志：服务崩溃/认证失败/磁盘错误"""
    import re

    def read_log(pattern: str) -> str:
        texts = []
        for f in sorted(log_dir.rglob('*')):
            if pattern.lower() in f.name.lower() and f.is_file():
                size = f.stat().st_size
                with open(f, 'r', encoding='utf-8', errors='replace') as fh:
                    texts.append(fh.read(min(size, 3 * 1024 * 1024)))
                if sum(len(t) for t in texts) > 5 * 1024 * 1024:
                    break
        return '\n'.join(texts)

    syslog_text = read_log('syslog') or read_log('messages')

    findings = []
    severity = "ok"
    stats = {}

    # Service failures (systemd service failed, process died)
    svc_fails = re.findall(r'(\S+\s+\d+\s+\d+:\d+:\d+).*?(?:service.*?failed|process.*?died|exited with|killed by signal)', syslog_text, re.IGNORECASE)
    stats['service_failures'] = len(svc_fails)

    # Authentication failures
    auth_fails = re.findall(r'(?:authentication failure|Failed password|invalid user|pam_unix.*auth)', syslog_text, re.IGNORECASE)
    stats['auth_failures'] = len(auth_fails)

    # Disk/storage errors
    disk_errs = re.findall(r'(?:I/O error|read error|write error|filesystem.*error|ext4.*error|btrfs.*error|xfs.*error)', syslog_text, re.IGNORECASE)
    stats['disk_errors'] = len(disk_errs)

    # Network errors
    net_errs = re.findall(r'(?:network.*unreachable|connection.*refused|timeout|dhcp.*fail|link.*down)', syslog_text, re.IGNORECASE)
    stats['network_errors'] = len(net_errs)

    # Build findings
    if stats['service_failures'] > 0:
        findings.append(f"🔴 服务失败 {stats['service_failures']} 次")
        severity = "warning"
    if stats['auth_failures'] > 10:
        findings.append(f"⚠️ 认证失败 {stats['auth_failures']} 次（可能有暴力破解尝试）")
        if severity == "ok": severity = "warning"
    elif stats['auth_failures'] > 0:
        findings.append(f"📝 认证失败 {stats['auth_failures']} 次")
    if stats['disk_errors'] > 0:
        findings.append(f"🔧 磁盘/文件系统错误 {stats['disk_errors']} 条")
        if severity == "ok": severity = "warning"
    if stats['network_errors'] > 0:
        findings.append(f"🌐 网络错误 {stats['network_errors']} 条")

    if not findings:
        findings.append("✅ 系统日志未发现明显异常")

    return {
        "title": "📋 Linux 系统日志",
        "severity": severity,
        "findings": findings,
        "stats": stats,
        "summary": f"服务失败{stats['service_failures']}次 / 认证失败{stats['auth_failures']}次 / 磁盘错误{stats['disk_errors']}条",
    }


def analyze_linux_summary(log_dir: Path) -> dict:
    """📊 Linux 综合总结"""
    results = {}
    findings = []
    severity = "ok"

    for atype in ["linux_overview", "linux_kernel", "linux_syslog"]:
        rp = REPORT_DIR / f"{jobs.get('_current_job_id','')}_{atype}.json"
        pass

    # Try reading cached reports by scanning report dir
    sev_map = {"critical": 3, "warning": 2, "ok": 1}
    max_sev = 1
    max_sev_name = "ok"

    for job_key in list(jobs.keys()):
        if jobs[job_key].get('tslog_path') == str(log_dir):
            current_job = job_key
            break
    else:
        current_job = None

    if current_job:
        for atype in ["linux_overview", "linux_kernel", "linux_syslog"]:
            rp = REPORT_DIR / f"{current_job}_{atype}.json"
            if rp.exists():
                try:
                    with open(rp, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        results[atype] = data
                        findings.extend(data.get('findings', [])[:3])
                        s = data.get('severity', 'ok')
                        if sev_map.get(s, 1) > max_sev:
                            max_sev = sev_map[s]
                            max_sev_name = s
                except:
                    pass

    if not findings:
        findings.append("请先运行内核诊断和系统日志分析")

    return {
        "title": "📊 Linux 综合总结",
        "severity": max_sev_name,
        "findings": findings,
        "detail": {k: {"title": v.get("title", k), "summary": v.get("summary", "")} for k, v in results.items()},
    }


ANALYZERS = {
    "overview": analyze_overview,
    "reboot": analyze_reboot,
    "hardware": analyze_hardware,
    "events": analyze_events,
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
    for ext_dir in UPLOAD_DIR.glob(f"extract_*{jid}*"):
        tslog, _ = find_log_dir(ext_dir)
        if tslog:
            tslog_path = str(tslog)
            # Normalize structure on restore (for non-standard layouts)
            if os_type == "windows" or os_type != "linux":
                normalize_log_structure(tslog)
            break
    if not tslog_path:
        for ext_dir in UPLOAD_DIR.glob("extract_*"):
            tslog, os_type2 = find_log_dir(ext_dir)
            if tslog and str(tslog).count(jid) > 0:
                tslog_path = str(tslog)
                if os_type2 == "windows" or os_type != "linux":
                    normalize_log_structure(tslog)
                break
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

    # Only allow readable text files + dmp
    ext = filepath.suffix.lower()
    if ext not in ('.txt', '.log', '.rom', '.csv', '.xml', '.ini', '.cfg', '.inf', '.evt', '.dmp'):
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

    if size > 500 * 1024:
        return JSONResponse({"error": "文件过大（>500KB），请下载后查看"}, status_code=400)

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

    # Accept .tar.gz, .tgz, .tzz as well as standard archives
    is_tar = filename.endswith('.tar.gz') or filename.endswith('.tgz') or filename.endswith('.tar') or filename.endswith('.tzz')
    if not is_tar and file_stem not in ('.7z', '.zip', '.rar'):
        return JSONResponse(
            {"error": f"不支持的文件格式，请上传 .7z / .zip / .rar (Windows) 或 .tar.gz / .tgz / .tar / .tzz (Linux/BMC)"},
            status_code=400)

    # Determine extension for filename
    if filename.endswith('.tar.gz'):
        save_ext = '.tar.gz'
    elif filename.endswith('.tgz'):
        save_ext = '.tgz'
    elif filename.endswith('.tzz'):
        save_ext = '.tzz'
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


# ─── AI Chat (DeepSeek function calling) ──────────────────

DEEPSEEK_API_KEY = "sk-your-deepseek-api-key"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"

# In-memory chat history per job
chat_sessions: dict = {}  # job_id -> list of {"role":"user"|"assistant"|"tool", "content":"..."}

CHAT_SYSTEM_PROMPT = """你是 Thinkstation 日志诊断专家助手，正在帮助用户分析一份诊断日志包（支持 Windows 和 Linux 系统）。

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
            for eid, lvl, ts, prov, root in iter_evtx(evtx_path, max_events=500):
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

                # Execute each tool
                for tc in msg["tool_calls"]:
                    func = tc["function"]
                    tool_result = _execute_tool(job_id, func["name"],
                                                json.loads(func["arguments"]) if isinstance(func["arguments"], str) else func["arguments"])
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8002)
