"""Windows diagnostic analyzers."""
from pathlib import Path
from datetime import datetime, timezone, timedelta
from collections import Counter
import json, re, os
from analyzers.dump_parser import parse_single_dump, get_bugcheck_info

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
