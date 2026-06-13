"""OS detection, archive extraction, encoding, history."""
import json, os, subprocess, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

BASE_DIR = Path("/opt/log-analyzer")
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
HISTORY_FILE = REPORT_DIR / "history.json"

MAX_EVENTS = 10000
CHINA_TZ = timezone(timedelta(hours=8))

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
    # Read first 4 bytes for BOM detection
    with open(filepath, 'rb') as f:
        head = f.read(4)
    if head[:3] == b'\xef\xbb\xbf':
        return 'utf-8-sig'
    if head[:2] == b'\xff\xfe':
        return 'utf-16-le'
    if head[:2] == b'\xfe\xff':
        return 'utf-16-be'
    # No BOM — try UTF-8 first (strict), then GBK (common for Chinese Windows)
    for enc in ['utf-8', 'gbk']:
        try:
            with open(filepath, 'r', encoding=enc) as f:
                f.read(4096)
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
    # tar.gz / tgz / tar / tar.xz — use 'xf' (GNU tar auto-detects compression)
    if any(filename.endswith(ext) for ext in ['.tar.gz', '.tgz', '.tar', '.tar.xz']):
        subprocess.run(['tar', 'xf', str(filepath), '-C', str(extract_dir)],
                       capture_output=True, timeout=180)
        return extract_dir
    ext = filepath.suffix.lower()
    if ext == '.7z':
        subprocess.run(['7z', 'x', '-y', str(filepath), f'-o{extract_dir}'],
                       capture_output=True, timeout=120)
    elif ext == '.rar':
        subprocess.run(['unrar', 'x', '-y', str(filepath), str(extract_dir)],
                       capture_output=True, timeout=120)
    elif ext == '.zip':
        try:
            extract_zip_safe(filepath, extract_dir)
        except Exception:
            # Fallback to unzip/7z if Python zipfile fails (password, corruption)
            result = subprocess.run(['unzip', '-o', '-O', 'gbk', str(filepath), '-d', str(extract_dir)],
                                    capture_output=True, timeout=120)
            if result.returncode != 0:
                subprocess.run(['7z', 'x', '-y', str(filepath), f'-o{extract_dir}'],
                               capture_output=True, timeout=120)
    else:
        result = subprocess.run(['unzip', '-o', str(filepath), '-d', str(extract_dir)],
                                capture_output=True, timeout=120)
        if result.returncode != 0:
            subprocess.run(['7z', 'x', '-y', str(filepath), f'-o{extract_dir}'],
                           capture_output=True, timeout=120)
    return extract_dir

def _fix_zip_filename(name: str) -> str:
    """Detect and fix garbled Chinese filenames from GBK-encoded zips.

    When a zip is created on Chinese Windows without the UTF-8 flag,
    filename bytes are stored as GBK but Python's zipfile reads them as
    cp437, producing box-drawing characters. Re-encoding cp437→gbk
    restores the original Chinese.
    """
    # If name already has CJK characters, it's correct — no fix needed
    if any('\u4e00' <= c <= '\u9fff' for c in name):
        return name
    try:
        fixed = name.encode('cp437').decode('gbk')
        # Verify: if fixed has CJK chars after re-encoding, it was GBK
        if any('\u4e00' <= c <= '\u9fff' for c in fixed):
            return fixed
    except (UnicodeEncodeError, UnicodeDecodeError):
        pass
    return name

def extract_zip_safe(filepath: Path, extract_dir: Path) -> Path:
    """Extract a zip file with GBK encoding detection for Chinese filenames.

    Uses Python's zipfile module which gives us byte-level control over
    filename encoding — 7z and unzip both fail on GBK-encoded zips.
    """
    import zipfile
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(filepath, 'r') as zf:
        for entry in zf.infolist():
            name = _fix_zip_filename(entry.filename)
            # Prevent path traversal attacks
            target = (extract_dir / name).resolve()
            if not str(target).startswith(str(extract_dir.resolve())):
                continue
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(entry) as src, open(target, 'wb') as dst:
                    dst.write(src.read())
    # Fix permissions for files extracted from zip (often have weird perms)
    for root, dirs, files in os.walk(extract_dir):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o755)
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)
    return extract_dir

def find_log_dir(extract_dir: Path) -> tuple[Optional[Path], str]:
    """Returns (log_dir_path, os_type): 'bmc', 'windows', 'linux', 'other', or 'unknown'.

    Detection order matters:
      Step 0  BMC    — must run first: BMC packages contain .dmp files
                        (firmware dumps) that would be misdetected as Windows.
      Step 1  Windows — tslog/ > oslog/ > .evtx/.dmp
      Step 2  Linux   — var/log/ > recursive syslog/kern.log/...
      Step 3  Other   — any .log/.txt files
      Step 4  Unknown — nothing recognizable

    Windows and Linux markers never overlap in practice, so Step 1/2 order
    doesn't affect correctness — but BMC must precede Windows.
    """
    # ── Step 0: BMC / XCC FFDC ──────────────────────────────────────────
    BMC_MARKERS = [
        'ffdc.log', 'bmc-err.log', 'kernel-err.log',
        'component_activity.log', 'syshealth.log',
        'security.log', 'system.log', 'bmc-warn.log',
        'xcc_pl_error.log', 'pfr_device.log', 'bmc-loop.log',
    ]
    for marker in BMC_MARKERS:
        for found in extract_dir.rglob(marker):
            if found.is_file():
                return extract_dir, "bmc"

    # ThinkServer variant: bmcos/ directory
    if (extract_dir / "bmcos").is_dir():
        return extract_dir, "bmc"
    if (extract_dir / "log" / "err.log").is_file() and \
       (extract_dir / "log" / "oemsys.log").is_file():
        return extract_dir, "bmc"

    # ── Step 1: Windows ─────────────────────────────────────────────────
    # 1a. Lenovo TS Log structure: tslog/ directory
    tslog = extract_dir / "tslog"
    if tslog.is_dir():
        return tslog, "windows"
    for path in extract_dir.rglob("tslog"):
        if path.is_dir():
            return path, "windows"

    # 1b. Legacy format: oslog/ directory
    if (extract_dir / "oslog").is_dir():
        return extract_dir, "windows"

    # 1c. Fallback: .evtx or .dmp files (Windows event logs / crash dumps)
    for ext in ["*.evtx", "*.dmp"]:
        for path in extract_dir.rglob(ext):
            parent = path.parent
            if parent == extract_dir:
                return extract_dir, "windows"
            # Return the top-level subdirectory containing these files
            for candidate in extract_dir.iterdir():
                if candidate.is_dir() and path.is_relative_to(candidate):
                    return candidate, "windows"

    # ── Step 2: Linux ───────────────────────────────────────────────────
    # 2a. Standard layout: var/log/ (sosreport, tar-based dumps)
    varlog = extract_dir / "var" / "log"
    if varlog.is_dir():
        return varlog, "linux"
    for path in extract_dir.rglob("var/log"):
        if path.is_dir():
            return path, "linux"

    # 2b. Recursive fallback: find Linux log files anywhere in the tree
    LINUX_LOGS = ['syslog', 'kern.log', 'messages', 'dmesg', 'auth.log']
    for fname in LINUX_LOGS:
        for found in extract_dir.rglob(fname):
            if found.is_file():
                return found.parent, "linux"

    # 2c. Chinese Linux log markers (UOS/Deepin log collection tools produce
    #     files like 内核日志.txt, 系统日志.txt, 启动日志.txt)
    CN_MARKERS = ['内核日志', '系统日志', '启动日志', 'dpkg日志', '开关机事件']
    for pattern in ['*.txt', '*.log']:
        for found in extract_dir.rglob(pattern):
            if found.is_file():
                for marker in CN_MARKERS:
                    if marker in found.name:
                        return found.parent, "linux"

    # ── Step 3: Other ───────────────────────────────────────────────────
    for pattern in ['*.log', '*.txt', '*.csv']:
        if list(extract_dir.glob(pattern)):
            return extract_dir, "other"
        for child in extract_dir.iterdir():
            if child.is_dir() and list(child.glob(pattern)):
                return child, "other"

    # ── Step 4: Unknown ─────────────────────────────────────────────────
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


# ── evtx parse cache (per file, in-memory) ──
_evtx_cache: dict = {}  # str(path) -> list of (eid, lvl, ts, prov, root)
_EVTX_DUMP_BIN = "/usr/local/bin/evtx_dump"


class _FakeDataElem:
    """Mimics lxml Element for evtx Data nodes."""
    def __init__(self, name: str, text: str):
        self.tag = '{http://schemas.microsoft.com/win/2004/08/events/event}Data'
        self.text = text
        self._name = name
    def get(self, attr: str, default=''):
        return self._name if attr == 'Name' else default


class _FakeRoot:
    """Mimics lxml Element for root evtx node."""
    def __init__(self, event_data: dict):
        self._children = [_FakeDataElem(k, str(v)) for k, v in event_data.items()
                          if not k.startswith('#') and not k.startswith('xmlns')]
    def findall(self, _xpath: str, _ns=None):
        return self._children
    def iter(self):
        return iter(self._children)


def _parse_evtx_rust(evtx_path: Path, max_events: int):
    """Parse evtx via Rust evtx_dump — ~1000x faster than python-evtx."""
    import subprocess, json as _json
    cmd = [_EVTX_DUMP_BIN, '--format', 'jsonl', str(evtx_path)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    count = 0
    try:
        for line in proc.stdout:
            if count >= max_events:
                break
            line = line.strip()
            if not line:
                continue
            try:
                evt = _json.loads(line).get('Event', {})
            except _json.JSONDecodeError:
                continue
            sysinfo = evt.get('System', {})
            eid = sysinfo.get('EventID', 0)
            if isinstance(eid, dict):
                eid = int(eid.get('#text', 0))
            elif isinstance(eid, str):
                eid = int(eid) if eid.isdigit() else 0
            lvl = sysinfo.get('Level', 0)
            if isinstance(lvl, dict):
                lvl = int(lvl.get('#text', 0))
            elif isinstance(lvl, str):
                lvl = int(lvl) if lvl.isdigit() else 0
            ts = ''
            tc = sysinfo.get('TimeCreated')
            if isinstance(tc, dict):
                ts = tc.get('#attributes', {}).get('SystemTime', '')
            prov = ''
            p = sysinfo.get('Provider')
            if isinstance(p, dict):
                prov = p.get('#attributes', {}).get('Name', '')
            ed = evt.get('EventData') or {}
            if not isinstance(ed, dict):
                ed = {}
            root = _FakeRoot(ed)
            count += 1
            yield eid, lvl, ts, prov, root
    finally:
        proc.kill()
        try:
            proc.wait(timeout=2)
        except Exception:
            pass


def _evtx_dump_available() -> bool:
    """Check if the Rust evtx_dump binary is installed."""
    import shutil
    return shutil.which(_EVTX_DUMP_BIN) is not None


def iter_evtx_cached(evtx_path: Path, max_events: int = MAX_EVENTS):
    """Cached version of iter_evtx — uses Rust evtx_dump if available, else python-evtx."""
    cache_key = str(evtx_path)
    cached = _evtx_cache.get(cache_key, [])

    # If cache already has enough, slice from it
    if len(cached) >= max_events:
        yield from cached[:max_events]
        return

    # Parse with Rust or fallback to Python
    parser = _parse_evtx_rust if _evtx_dump_available() else iter_evtx
    new_results = list(parser(evtx_path, max_events=max_events))
    _evtx_cache[cache_key] = new_results
    yield from new_results


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
