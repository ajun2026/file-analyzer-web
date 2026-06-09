"""Linux diagnostic analyzers."""
from pathlib import Path
from datetime import datetime
from collections import Counter
import re

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
