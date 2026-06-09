"""OS detection, archive extraction, encoding, history."""
import json, os, subprocess, uuid
from pathlib import Path
from typing import Optional

BASE_DIR = Path("/opt/log-analyzer")
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"

MAX_EVENTS = 10000

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
