#!/usr/bin/env python3
"""
Windows Dump (.dmp) 解析器 v2
支持 Minidump + PAGEDU64 + 完整内存转储
用法: python3 dmp_parser.py <dmp文件路径>
"""
import sys, json, struct, re, subprocess, os
from datetime import datetime

# === Minidump 签名 ===
MINIDUMP_SIGNATURE = b'MDMP'

# === 处理器架构 ===
ARCH_NAMES = {0: 'x86', 5: 'ARM', 9: 'AMD64 (x64)', 12: 'ARM64', 0xFFFF: 'Unknown'}
ARCH_BITS = {0: 32, 9: 64, 12: 64}

# === 异常代码对照 ===
EXCEPTION_CODES = {
    0xC0000005: 'ACCESS_VIOLATION (内存访问违规)',
    0xC0000017: 'NO_MEMORY (内存不足)',
    0xC000001D: 'ILLEGAL_INSTRUCTION (非法指令)',
    0xC00000FD: 'STACK_OVERFLOW (堆栈溢出)',
    0xC0000135: 'DLL_NOT_FOUND (DLL 未找到)',
    0xC0000409: 'STACK_BUFFER_OVERRUN (堆栈缓冲区溢出)',
    0xC0000417: 'INVALID_CRUNTIME_PARAMETER',
    0x80000003: 'BREAKPOINT (断点)',
    0xE0000008: 'WHEA_UNCORRECTABLE_ERROR (硬件致命错误)',
    0xE0434352: 'CLR_EXCEPTION (.NET 异常)',
    0xE06D7363: 'CPP_EXCEPTION (C++ 异常)',
    0xC0000006: 'IN_PAGE_ERROR (页面调入错误)',
}

# === BugCheck 代码对照 ===
BUGCHECK_CODES = {
    0x00000001: 'APC_INDEX_MISMATCH',
    0x0000000A: 'IRQL_NOT_LESS_OR_EQUAL (驱动访问了错误的内存地址)',
    0x0000001A: 'MEMORY_MANAGEMENT (严重内存管理错误)',
    0x0000001E: 'KMODE_EXCEPTION_NOT_HANDLED (内核模式异常未处理)',
    0x00000024: 'NTFS_FILE_SYSTEM (NTFS文件系统错误)',
    0x0000002E: 'DATA_BUS_ERROR (数据总线错误 - 内存硬件)',
    0x0000003B: 'SYSTEM_SERVICE_EXCEPTION (系统服务异常)',
    0x0000003D: 'INTERRUPT_EXCEPTION_NOT_HANDLED',
    0x00000050: 'PAGE_FAULT_IN_NONPAGED_AREA (页面错误)',
    0x0000007E: 'SYSTEM_THREAD_EXCEPTION_NOT_HANDLED (系统线程异常)',
    0x0000007F: 'UNEXPECTED_KERNEL_MODE_TRAP (意外内核陷阱 - CPU)',
    0x0000008E: 'KERNEL_MODE_EXCEPTION_NOT_HANDLED',
    0x0000009F: 'DRIVER_POWER_STATE_FAILURE (驱动电源状态故障)',
    0x000000A0: 'INTERNAL_POWER_ERROR',
    0x000000A5: 'ACPI_BIOS_ERROR',
    0x000000BE: 'ATTEMPTED_WRITE_TO_READONLY_MEMORY',
    0x000000C2: 'BAD_POOL_CALLER (内存池错误)',
    0x000000C4: 'DRIVER_VERIFIER_DETECTED_VIOLATION',
    0x000000C5: 'DRIVER_CORRUPTED_EXPOOL',
    0x000000D1: 'DRIVER_IRQL_NOT_LESS_OR_EQUAL (驱动IRQL错误)',
    0x000000D5: 'DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL',
    0x000000E2: 'MANUALLY_INITIATED_CRASH (手动触发崩溃)',
    0x000000E3: 'RESOURCE_NOT_OWNED',
    0x000000E4: 'WORKER_INVALID',
    0x000000EF: 'CRITICAL_PROCESS_DIED (关键进程已死)',
    0x000000F4: 'CRITICAL_OBJECT_TERMINATION (关键对象终止)',
    0x000000FC: 'ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY',
    0x00000101: 'CLOCK_WATCHDOG_TIMEOUT (时钟看门狗超时 - CPU)',
    0x00000109: 'CRITICAL_STRUCTURE_CORRUPTION (关键结构损坏 - 驱动)',
    0x00000116: 'VIDEO_TDR_FAILURE (显卡超时恢复失败)',
    0x00000117: 'VIDEO_TDR_TIMEOUT_DETECTED (显卡超时)',
    0x00000119: 'VIDEO_SCHEDULER_INTERNAL_ERROR (显卡调度器错误)',
    0x00000124: 'WHEA_UNCORRECTABLE_ERROR (硬件错误 - CPU/PCIe)',
    0x00000133: 'DPC_WATCHDOG_VIOLATION (DPC看门狗超时)',
    0x00000139: 'KERNEL_SECURITY_CHECK_FAILURE',
    0x00000141: 'VIDEO_ENGINE_TIMEOUT_DETECTED',
    0x00000144: 'BUGCODE_USB3_DRIVER',
    0x00000153: 'KERNEL_LOCK_ENTRY_LEAKED_ON_THREAD_TERMINATION',
    0x00000154: 'UNEXPECTED_STORE_EXCEPTION',
    0x00000157: 'KERNEL_THREAD_PRIORITY_FLOOR_VIOLATION',
    0x00000161: 'LIVEDUMP_CODE_OVERFLOW',
    0x00000162: 'LIVEDUMP_CODE',
    0xC000021A: 'STATUS_SYSTEM_PROCESS_TERMINATED',
    0xC0000221: 'STATUS_IMAGE_CHECKSUM_MISMATCH',
}

# === Dump 类型映射 ===
DUMP_TYPES = {
    0: 'None',
    1: 'Full (完整内存转储)',
    2: 'Kernel (内核转储)',
    3: 'Small (小型转储)',
    4: 'Automatic/Triage (自动分类转储)',
    5: 'Active (活动转储)',
    6: 'KernelFull (内核完整)',
    7: 'KernelSmall',
    15: 'Automatic/Triage (Win11 自动转储)',
}

STREAM_TYPES = {
    3: 'ThreadListStream', 4: 'ModuleListStream', 5: 'MemoryListStream',
    6: 'ExceptionStream', 7: 'SystemInfoStream', 15: 'MiscInfoStream',
    1197932545: 'Memory64ListStream',
}


def fatal(msg):
    print(json.dumps({'error': msg}, ensure_ascii=False))
    sys.exit(0)


def format_size(size):
    if size < 1024: return f'{size} B'
    if size < 1024 * 1024: return f'{size/1024:.1f} KB'
    if size < 1024 * 1024 * 1024: return f'{size/(1024*1024):.1f} MB'
    return f'{size/(1024*1024*1024):.2f} GB'


def extract_strings(filepath, max_size=10 * 1024 * 1024):
    """提取可读字符串"""
    try:
        output = subprocess.check_output(['strings', '-n', '4', filepath], timeout=15)
        return output.decode('utf-8', errors='replace').split('\n')
    except:
        try:
            output = subprocess.check_output(
                ['head', '-c', str(max_size), filepath], timeout=15
            )
            result = []
            current = b''
            for b in output:
                if 0x20 <= b <= 0x7E:
                    current += bytes([b])
                else:
                    if len(current) >= 4:
                        result.append(current.decode('ascii', errors='replace'))
                    current = b''
            return result
        except:
            return []


def find_bugcheck_from_evtx(dmp_path):
    """Extract BugCheck from evtx files (fast raw search)"""
    dmp_dir = os.path.dirname(dmp_path)
    parent_dir = os.path.dirname(dmp_dir)
    evtx_path = os.path.join(parent_dir, 'oslog', 'System.evtx')
    
    if not os.path.isfile(evtx_path):
        return None
    
    try:
        import re as _re
        evtx_size = os.path.getsize(evtx_path)
        read_limit = min(evtx_size, 5 * 1024 * 1024)
        output = subprocess.check_output(
            ['head', '-c', str(read_limit), evtx_path], timeout=10
        )
        text = output.decode('utf-8', errors='replace')
        
        crashes = []
        # Pattern: 0x00000124 (0x..., 0x..., 0x..., 0x...)
        for m in _re.finditer(
            r'0x([0-9a-fA-F]{8})\s*\(\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*\)',
            text
        ):
            code = int(m.group(1), 16)
            params = [int(m.group(i), 16) for i in range(2, 6)]
            crashes.append({'code': code, 'params': params, 'time': ''})
        
        # Also from BugcheckCode field in EID 41
        for m in _re.finditer(r'BugcheckCode[:\s]+(\d+)', text):
            bc_val = int(m.group(1))
            if 1 <= bc_val <= 0xFFF:
                ctx_start = max(0, m.start() - 300)
                ctx_end = min(len(text), m.end() + 500)
                ctx = text[ctx_start:ctx_end]
                p_matches = _re.findall(r'BugcheckParameter\d+[:\s]+(0x[0-9a-fA-F]+)', ctx)
                params = []
                for pm in p_matches:
                    try: params.append(int(pm, 16))
                    except: pass
                crashes.append({'code': bc_val, 'params': params, 'time': ''})
        
        if crashes:
            return crashes[0]
    except:
        pass
    
    # Fallback: full Evtx parse for small files
    try:
        from Evtx.Evtx import Evtx
        import re as _re
        evtx_size = os.path.getsize(evtx_path)
        if evtx_size > 8 * 1024 * 1024:
            return None
        
        crashes = []
        with Evtx(evtx_path) as log:
            for i, rec in enumerate(log.records()):
                if i > 5000: break
                try:
                    xml = rec.xml()
                except: continue
                eid_m = _re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
                if not eid_m or int(eid_m.group(1)) != 1001:
                    continue
                ts_m = _re.search(r'<TimeCreated SystemTime="([^"]+)"', xml)
                ts = ts_m.group(1)[:19] if ts_m else ''
                datas = {}
                for dm in _re.finditer(r'<Data Name="([^"]+)">([^<]*)</Data>', xml):
                    datas[dm.group(1)] = dm.group(2)
                param1 = datas.get('param1', '')
                m2 = _re.match(r'(0x[0-9a-fA-F]+)\s*\((.*)\)', param1)
                if m2:
                    code = int(m2.group(1), 16)
                    params_str = m2.group(2)
                    params = [int(p.strip(), 16) for p in params_str.split(',') if p.strip()]
                    crashes.append({'time': ts, 'code': code, 'params': params})
        if crashes:
            return crashes[-1]
    except:
        pass
    return None
def get_crash_analysis(bugcheck_code, params, strings_data):
    """根据 BugCheck 代码给出分析建议"""
    analysis = []
    
    if bugcheck_code in (0x00000116, 0x00000117, 0x00000119, 0x00000141):
        analysis.append("⚠ GPU/显卡驱动问题")
        analysis.append("→ 显卡驱动超时或崩溃 (TDR)")
        analysis.append("→ 建议: 使用 DDU 卸载后重装最新显卡驱动")
        analysis.append("→ 检查显卡散热和电源供应")
    elif bugcheck_code == 0x00000133:
        analysis.append("⚠ DPC 看门狗超时")
        analysis.append("→ 通常是驱动问题 (SSD/网卡/显卡驱动)")
        analysis.append("→ 建议: 更新所有驱动, 特别是存储和网络驱动")
    elif bugcheck_code == 0x00000050:
        analysis.append("⚠ 页面错误 — 驱动访问无效内存")
        analysis.append("→ 可能是驱动 bug 或内存硬件故障")
        analysis.append("→ 建议: 运行 Windows 内存诊断 / MemTest86")
    elif bugcheck_code == 0x0000003B:
        code_name = ''
        if params and params[0] == 0xC0000005:
            code_name = ' (子类型: ACCESS_VIOLATION 内存访问违规)'
        analysis.append("⚠ 系统服务异常 (SYSTEM_SERVICE_EXCEPTION)" + code_name)
        analysis.append("→ 内核态系统服务调用异常")
        analysis.append("→ 常见原因: 第三方驱动 bug / 显卡驱动 / 反病毒软件")
    elif bugcheck_code == 0x000000D1:
        analysis.append("⚠ 驱动 IRQL 错误 (DRIVER_IRQL_NOT_LESS_OR_EQUAL)")
        analysis.append("→ 驱动在错误的 IRQL 级别访问内存")
        analysis.append("→ 建议: 检查最近安装或更新的驱动")
    elif bugcheck_code == 0x0000000A:
        analysis.append("⚠ IRQL 错误 (IRQL_NOT_LESS_OR_EQUAL)")
        analysis.append("→ 内核在错误的 IRQL 级别访问分页内存")
        analysis.append("→ 通常是驱动 bug")
    elif bugcheck_code == 0x000000EF:
        analysis.append("⚠ 关键进程终止 (CRITICAL_PROCESS_DIED)")
        analysis.append("→ Windows 关键系统进程意外终止")
        analysis.append("→ 可能原因: 系统文件损坏/磁盘错误/恶意软件")
    elif bugcheck_code == 0x0000007E:
        code_name = ''
        if params and (params[0] & 0xFFFFFFFF) == 0xC0000005:
            code_name = ' (ACCESS_VIOLATION)'
        analysis.append("⚠ 系统线程异常 (SYSTEM_THREAD_EXCEPTION_NOT_HANDLED)" + code_name)
        analysis.append("→ 系统线程中的未处理异常")
    elif bugcheck_code == 0x00000124:
        analysis.append("⚠ 硬件级别故障 (WHEA)")
        analysis.append("→ CPU/PCIe/Memory 硬件错误")
        analysis.append("→ 检查 CPU 电压/散热/超频")
    
    return analysis


def detect_gpu_type(strings_data):
    """检测 GPU 类型"""
    text = ' '.join(strings_data[:5000]) if isinstance(strings_data, list) else strings_data
    has_intel_gpu = False
    for kw in ['igdkmd', 'igfx', 'IntelGraphics', 'SCHED_UM_PAGE_FAULT', 'GUC_', 'G2H']:
        if kw.upper() in text.upper():
            has_intel_gpu = True
            break
    if 'igfx' in text.lower() or has_intel_gpu:
        return 'Intel 集成显卡 (可能存在问题)'
    if 'NVIDIA' in text or 'nvlddmkm' in text.lower():
        return 'NVIDIA'
    if 'AMD' in text or 'atikmpag' in text.lower():
        return 'AMD'
    if 'GenuineIntel' in text:
        return 'Intel CPU (集成显卡可能)'
    return '未知'


def analyze_intel_gpu_strings(strings_data):
    """分析 Intel GPU 相关错误"""
    gpu_keywords = [
        'ENGINE_ERROR', 'ENGINE_RESET', 'ENGINE_UNCORRECTABLE',
        'ERROR_GUC', 'ERROR_SCHED', 'ERROR_CCSWA', 'ERROR_CTB',
        'ERROR_FW', 'ERROR_HOST_TO_GUC', 'ERROR_ENGINE_RESET',
        'ERROR_UM_PAGE_FAULT', 'ERROR_GFX', 'ERROR_DOORBELL',
        'ERROR_BOOTROM', 'ERROR_FW_INVALID', 'ERROR_DISPLAY',
        'PAGE_FAULT', 'PREEMPTION_TIMEOUT', 'SCHED_RESET',
        'SCHED_ABORT', 'VIDEO_TDR',
    ]
    found = set()
    for s in strings_data:
        s = s.strip()
        if len(s) < 8 or len(s) > 300:
            continue
        for kw in gpu_keywords:
            if kw in s:
                found.add(s[:200])
                break
    return sorted(found)[:30]


def parse_full_dump(filepath, fsize):
    """解析完整内存转储 / PAGEDU64"""
    report = []
    report.append("╔════════════════════════════════════════════════╗")
    report.append("║   Windows 内存转储分析                         ║")
    report.append("╚════════════════════════════════════════════════╝")
    report.append("")
    
    try:
        f = open(filepath, 'rb')
        hdr = f.read(0x4000)
        f.close()
        
        sig = hdr[:8]
        format_name = "Unknown"
        dt = 0
        
        if sig[:4] == b'PAGE':
            valid = sig[4:8]
            if valid == b'DU64':
                format_name = "PAGEDU64 (Windows 10+)"
                dt = struct.unpack_from('<I', hdr, 0x08)[0]
            elif valid == b'DUMP':
                format_name = "PAGEDUMP"
                dt = struct.unpack_from('<I', hdr, 0x08)[0]
            else:
                format_name = f"PAGE/{valid.decode('ascii', errors='replace')}"
                dt = struct.unpack_from('<I', hdr, 0x08)[0]
        elif sig[:4] == b'DUMP':
            format_name = "DUMP"
            dt = struct.unpack_from('<I', hdr, 0x08)[0]
        elif sig[:4] == b'KDBG':
            format_name = "KDBG"
            dt = 0
        
        report.append(f"  格式:        {format_name}")
        report.append(f"  转储类型:    {DUMP_TYPES.get(dt, f'Unknown({dt})')}")
        report.append(f"  文件大小:    {format_size(fsize)}")
        
        # 尝试读取系统时间
        try:
            systime = struct.unpack_from('<Q', hdr, 0x18)[0]
            if 0 < systime < 0xFFFFFFFFFFFFFFFF:
                ft = systime / 10000000.0 - 11644473600
                if 2015 < datetime.utcfromtimestamp(ft).year < 2100:
                    ts = datetime.utcfromtimestamp(ft)
                    report.append(f"  崩溃时间:    {ts.strftime('%Y-%m-%d %H:%M:%S')} UTC")
        except:
            pass
        report.append("")
        
        # 提取字符串
        strings_data = extract_strings(filepath)
        
        # === BugCheck 检测 ===
        report.append("━" * 48)
        report.append("【⚠ BugCheck 崩溃信息】")
        report.append("")
        
        # 方法1: 从 evtx 文件获取
        evtx_crash = find_bugcheck_from_evtx(filepath)
        
        if evtx_crash:
            bc = evtx_crash['code']
            bc_name = BUGCHECK_CODES.get(bc, 'Unknown')
            report.append(f"  来源:        System.evtx (事件 1001)")
            report.append(f"  时间:        {evtx_crash['time']}")
            report.append(f"  BugCheck:    0x{bc:08X}  →  {bc_name}")
            if evtx_crash.get('params'):
                params = evtx_crash['params']
                for i, p in enumerate(params, 1):
                    if p != 0:
                        fmt = f"0x{{:0{16 if p > 0xFFFFFFFF else 8}X}}"
                        report.append(f"  参数{i}:       {fmt.format(p)}")
                        if i == 1 and (p & 0xFFFFFFFF) in EXCEPTION_CODES:
                            report.append(f"              → {EXCEPTION_CODES[p & 0xFFFFFFFF]}")
            report.append("")
            
            # 分析建议
            analysis = get_crash_analysis(bc, evtx_crash.get('params', []), strings_data)
            if analysis:
                report.append("  【可能的原因分析】")
                for line in analysis:
                    report.append(f"  {line}")
                report.append("")
        else:
            # 尝试从 PAGEDU64 header offset 0x38 读取 BugCheckCode
            found_bc = False
            try:
                bc_hdr = struct.unpack_from('<I', hdr, 0x38)[0]
                if bc_hdr in BUGCHECK_CODES:
                    report.append(f"  BugCheck:    0x{bc_hdr:08X}  ->  {BUGCHECK_CODES[bc_hdr]}")
                    # Read params from offsets after "PAGE" section header
                    for pi, po in enumerate([0x48, 0x50, 0x58, 0x60], 1):
                        try:
                            param = struct.unpack_from('<Q', hdr, po)[0]
                            report.append(f"  Parameter{pi}:  0x{param:016X}")
                        except:
                            break
                    report.append("")
                    found_bc = True
            except:
                pass
            
            if not found_bc:
                # 尝试从 KDBG 块获取
                kdbg_idx = hdr.find(b'KDBG')
                if kdbg_idx > 0:
                    # KDDEBUGGER_DATA64 从 KDBG + 0x10 开始
                    kd_start = kdbg_idx + 0x18  # header (16) + OwnerTag(4) + Size(4) = 24, then data starts
                    # 在 KDDEBUGGER_DATA64 中搜索 BugCheck (0x130~0x200范围)
                    found_bc = False
                    for offset in range(0x100, min(0x400, len(hdr) - kd_start - 24)):
                        try:
                            bc_candidate = struct.unpack_from('<I', hdr, kd_start + offset)[0]
                            if bc_candidate in BUGCHECK_CODES:
                                # 验证: 后面应有合理的参数
                                params = struct.unpack_from('<QQQQ', hdr, kd_start + offset + 4)
                                param_list = list(params)
                                # 至少1个非零参数或参数为有效内核地址
                                non_zero = [p for p in param_list if p != 0]
                                if len(non_zero) > 0:
                                    report.append(f"  BugCheck:    0x{bc_candidate:08X}  →  {BUGCHECK_CODES[bc_candidate]}")
                                    for i, p in enumerate(param_list, 1):
                                        if p != 0:
                                            report.append(f"  参数{i}:       0x{p:016X}")
                                    report.append("")
                                    found_bc = True
                                    break
                        except:
                            continue
                
                    if not found_bc:
                        report.append("  BugCheck:    未在 KDBG 块中检测到")
                        report.append("  (PAGEDU64 格式的 BugCheck 代码位置因 Windows 版本而异)")
                        report.append("")
                else:
                    report.append("  BugCheck:    未检测到")
                    report.append("  → 建议使用 WinDbg (!analyze -v) 进行分析")
                    report.append("")
        
            # === 系统版本 ===
        report.append("━" * 48)
        report.append("【系统版本信息】")
        found_ver = set()
        for s in strings_data:
            s = s.strip()
            if 15 < len(s) < 200 and 'Windows' in s:
                found_ver.add(s[:150])
        if found_ver:
            for s in sorted(found_ver)[:6]:
                report.append(f"  → {s}")
        else:
            # 从字符串中找 Build 号
            for s in strings_data:
                s = s.strip()
                if 'fre' in s.lower() and ('release' in s.lower() or 'build' in s.lower()):
                    found_ver.add(s[:150])
            if found_ver:
                for s in sorted(found_ver)[:4]:
                    report.append(f"  → {s}")
            else:
                report.append("  (未检测到)")
        report.append("")
        
        # === GPU 分析 ===
        gpu_type = detect_gpu_type(strings_data)
        report.append("━" * 48)
        report.append(f"【GPU 显卡检测】{gpu_type}")
        report.append("")
        
        if 'Intel' in gpu_type:
            gpu_strings = analyze_intel_gpu_strings(strings_data)
            if gpu_strings:
                report.append("  发现 Intel GPU 引擎错误关键词:")
                for s in gpu_strings[:20]:
                    report.append(f"  ⚡ {s}")
                report.append("")
                report.append("  分析: 转储中包含大量 Intel GPU 调度器/引擎错误字符串,")
                report.append("  强烈指向 Intel 集成显卡驱动问题。")
                report.append("  建议: 更新 Intel Arc & Iris Graphics 驱动到最新版本。")
                report.append("")
        
        # === 关键驱动信息 ===
        report.append("━" * 48)
        report.append("【关键驱动/错误字符串】")
        report.append("")
        
        driver_keywords = [
            '.sys', 'DRIVER', 'FATAL', 'CRITICAL', 'TIMEOUT',
            'crash', 'hang', 'freeze', 'deadlock',
            'ntoskrnl', 'ntkrnl', 'hal', 'wdf', 'fltmgr',
            'ntfs', 'storport', 'ndis', 'tcpip',
        ]
        
        important = set()
        for s in strings_data:
            s = s.strip()
            if 4 < len(s) < 400:
                lower = s.lower()
                if any(kw.lower() in lower for kw in driver_keywords):
                    important.add(s)
        
        for s in sorted(important)[:30]:
            report.append(f"  → {s}")
        report.append("")
        
        # === 分析建议 ===
        report.append("━" * 48)
        report.append("【分析建议】")
        report.append("")
        report.append("  专业分析方案 (需 Windows 环境):")
        report.append("  1. WinDbg: windbg -z file.dmp → 运行 !analyze -v")
        report.append("  2. BlueScreenView: 快速查看崩溃信息")
        report.append("")
        report.append("  Linux 环境方案:")
        report.append("  1. Volatility3: pip install volatility3")
        report.append("  2. 字符串: strings file.dmp | grep -iE 'error|crash'")
        
        return '\n'.join(report)
        
    except Exception as e:
        return f"\n[解析错误: {e}]\n"


def read_system_info(f, rva, arch_bits):
    """读取 Minidump SystemInfoStream"""
    f.seek(rva)
    info = {}
    proc_arch = struct.unpack('<H', f.read(2))[0]
    proc_level = struct.unpack('<H', f.read(2))[0]
    proc_rev = struct.unpack('<H', f.read(2))[0]
    info['cpu_arch'] = ARCH_NAMES.get(proc_arch, f'Unknown({proc_arch})')
    info['cpu_level'] = proc_level
    info['cpu_revision'] = proc_rev
    f.read(2)
    if proc_arch == 0:
        f.read(208)
    elif proc_arch in (9, 12):
        info['processor_features'] = hex(struct.unpack('<Q', f.read(8))[0])
        info['vendor_id'] = f.read(12).decode('ascii', errors='replace').replace('\x00', '').strip()
        info['version_info'] = hex(struct.unpack('<I', f.read(4))[0])
    platform_id = struct.unpack('<I', f.read(4))[0]
    os_csdversion = f.read(32).decode('utf-16le', errors='replace').split('\x00')[0].strip()
    os_major = struct.unpack('<I', f.read(4))[0]
    os_minor = struct.unpack('<I', f.read(4))[0]
    os_build = struct.unpack('<H', f.read(2))[0]
    os_platform = struct.unpack('<H', f.read(2))[0]
    f.read(4)
    info['os'] = f"Windows NT {os_major}.{os_minor} Build {os_build}"
    info['os_csdversion'] = os_csdversion
    if os_platform == 2:
        info['product_type'] = struct.unpack('B', f.read(1))[0]
    return info


def read_exception_stream(f, rva, arch_bits):
    f.seek(rva)
    thread_id = struct.unpack('<I', f.read(4))[0]
    f.read(4)
    exc_code = struct.unpack('<I', f.read(4))[0]
    exc_flags = struct.unpack('<I', f.read(4))[0]
    f.read(4 if arch_bits == 32 else 8)
    exc_address = struct.unpack('<Q' if arch_bits == 64 else '<I', f.read(8 if arch_bits == 64 else 4))[0]
    num_params = struct.unpack('<I', f.read(4))[0]
    f.read(4)
    param_fmt = '<Q' if arch_bits == 64 else '<I'
    param_size = 8 if arch_bits == 64 else 4
    params = [struct.unpack(param_fmt, f.read(param_size))[0] for _ in range(min(num_params, 15))]
    exc = {'thread_id': thread_id,
           'code': f"0x{exc_code:08X}",
           'code_name': EXCEPTION_CODES.get(exc_code, 'UNKNOWN'),
           'flags': f"0x{exc_flags:08X}",
           'address': f"0x{exc_address:016X}" if arch_bits == 64 else f"0x{exc_address:08X}",
           'num_params': num_params}
    if params:
        exc['params'] = params
    return exc


def read_module_list(f, rva, arch_bits):
    f.seek(rva)
    num_modules = struct.unpack('<I', f.read(4))[0]
    modules = []
    ptr_fmt = '<Q' if arch_bits == 64 else '<I'
    ptr_size = 8 if arch_bits == 64 else 4
    base_fmt = f"0x{{:0{16 if arch_bits == 64 else 8}X}}"
    for i in range(num_modules):
        base = struct.unpack(ptr_fmt, f.read(ptr_size))[0]
        size = struct.unpack('<I', f.read(4))[0]
        f.read(8)
        name_rva = struct.unpack('<I', f.read(4))[0]
        saved_pos = f.tell()
        short_name = '<unknown>'
        try:
            f.seek(name_rva)
            raw_name = f.read(256)
            name = raw_name.decode('utf-16le', errors='replace').split('\x00')[0]
            short_name = name.rsplit('\\', 1)[-1] if '\\' in name else name.rsplit('/', 1)[-1] if '/' in name else name
        except: pass
        f.seek(saved_pos)
        f.read(8)
        cv_rva = struct.unpack('<I', f.read(4))[0]
        cv_size = struct.unpack('<I', f.read(4))[0]
        f.read(16)
        pdb_info = ''
        if cv_rva and cv_size:
            saved_pos2 = f.tell()
            try:
                f.seek(cv_rva)
                cv_sig = struct.unpack('<I', f.read(4))[0]
                if cv_sig == 0x53445352:
                    f.read(16)
                    age = struct.unpack('<I', f.read(4))[0]
                    pdb_name = f.read(cv_size - 24).decode('utf-8', errors='replace').split('\x00')[0]
                    pdb_info = f"{pdb_name} (age={age})"
            except: pass
            f.seek(saved_pos2)
        modules.append({'name': short_name, 'base': base_fmt.format(base),
                        'size': size, 'pdb': pdb_info})
    return modules


def read_thread_list(f, rva, arch_bits):
    f.seek(rva)
    num_threads = struct.unpack('<I', f.read(4))[0]
    threads = []
    ptr_fmt = '<Q' if arch_bits == 64 else '<I'
    ptr_size = 8 if arch_bits == 64 else 4
    fmt = f"0x{{:0{16 if arch_bits == 64 else 8}X}}"
    for i in range(num_threads):
        tid = struct.unpack('<I', f.read(4))[0]
        f.read(8)
        priority = struct.unpack('<I', f.read(4))[0]
        f.read(ptr_size)
        ctx_rva = struct.unpack('<I', f.read(4))[0]
        ctx_size = struct.unpack('<I', f.read(4))[0]
        t = {'thread_id': tid, 'priority': priority}
        if ctx_rva and ctx_size >= 4:
            saved_pos = f.tell()
            try:
                if arch_bits == 64 and ctx_size >= 0x100:
                    f.seek(ctx_rva + 0xF8)
                    t['rip'] = fmt.format(struct.unpack('<Q', f.read(8))[0])
                elif arch_bits == 32 and ctx_size >= 0xCC:
                    f.seek(ctx_rva + 0xB8)
                    t['eip'] = fmt.format(struct.unpack('<I', f.read(4))[0])
            except: pass
            f.seek(saved_pos)
        threads.append(t)
    return threads


def parse_minidump(f, fsize, filepath):
    f.seek(4)
    version = struct.unpack('<I', f.read(4))[0]
    num_streams = struct.unpack('<I', f.read(4))[0]
    stream_dir_rva = struct.unpack('<I', f.read(4))[0]
    f.read(8 + 4)
    flags = struct.unpack('<Q', f.read(8))[0]
    f.seek(stream_dir_rva)
    streams = {}
    for i in range(num_streams):
        st, sz, rv = struct.unpack('<III', f.read(12))
        streams[st] = {'size': sz, 'rva': rv}
    arch_bits = 64
    if 7 in streams:
        f.seek(streams[7]['rva'])
        arch_bits = ARCH_BITS.get(struct.unpack('<H', f.read(2))[0], 64)
    
    report = []
    report.append("╔══════════════════════════════════════════╗")
    report.append("║   Windows Minidump 分析报告              ║")
    report.append("╚══════════════════════════════════════════╝")
    report.append("")
    report.append(f"  架构: {arch_bits}-bit | 版本: v{version}")
    report.append(f"  文件大小: {format_size(fsize)} | 数据流: {num_streams} 个")
    report.append("")
    
    if 7 in streams:
        try:
            si = read_system_info(f, streams[7]['rva'], arch_bits)
            report.append("━" * 44)
            report.append("【系统信息】")
            report.append(f"  OS: {si.get('os', 'N/A')}")
            report.append(f"  CPU架构: {si.get('cpu_arch', 'N/A')}")
            if 'vendor_id' in si:
                report.append(f"  CPU厂商: {si['vendor_id']}")
            report.append("")
        except: pass
    
    exc = None
    if 6 in streams:
        try:
            exc = read_exception_stream(f, streams[6]['rva'], arch_bits)
            report.append("━" * 44)
            report.append("【⚠ 崩溃异常信息】")
            report.append(f"  异常线程: TID={exc['thread_id']} (0x{exc['thread_id']:X})")
            report.append(f"  异常代码: {exc['code']}")
            report.append(f"  异常含义: {exc['code_name']}")
            report.append(f"  异常地址: {exc['address']}")
            if exc.get('params'):
                report.append(f"  异常参数: {', '.join([hex(p) for p in exc['params']])}")
            report.append("")
        except: pass
    
    modules_data = []
    if 4 in streams:
        try:
            modules_data = read_module_list(f, streams[4]['rva'], arch_bits)
            report.append("━" * 44)
            report.append(f"【已加载模块】({len(modules_data)} 个)")
            if exc:
                exc_addr = int(exc['address'], 16)
                for mod in modules_data:
                    base = int(mod['base'], 16)
                    if base <= exc_addr < base + mod['size']:
                        offset = exc_addr - base
                        report.append(f"  ▶ 崩溃模块: {mod['name']}+0x{offset:X}")
                        if mod.get('pdb'):
                            report.append(f"     PDB: {mod['pdb']}")
                        break
            report.append("")
            sys_prefixes = ['nt', 'win32k', 'kernel', 'ntdll', 'hal', 'ntkrnl', 'wow64', 'csrss', 'KERNELBASE']
            third_party = []
            for mod in modules_data:
                is_sys = any(mod['name'].lower().startswith(p.lower()) for p in sys_prefixes)
                if is_sys or mod['name'].lower().endswith('.sys'):
                    report.append(f"    {mod['base']}  {mod['name']} ({format_size(mod['size'])})")
                else:
                    third_party.append(mod)
            if third_party:
                report.append(f"\n  ▶ 第三方模块 ({len(third_party)} 个):")
                for mod in third_party[:25]:
                    report.append(f"    {mod['base']}  {mod['name']} ({format_size(mod['size'])})")
                if len(third_party) > 25:
                    report.append(f"    ... 还有 {len(third_party) - 25} 个")
            report.append("")
        except: pass
    
    if 3 in streams:
        try:
            threads = read_thread_list(f, streams[3]['rva'], arch_bits)
            report.append("━" * 44)
            report.append(f"【线程信息】({len(threads)} 个)")
            if exc:
                crash_tid = exc['thread_id']
                for t in threads:
                    if t['thread_id'] == crash_tid:
                        ip_key = 'rip' if arch_bits == 64 else 'eip'
                        if ip_key in t:
                            report.append(f"  崩溃线程 TID={crash_tid}: 指令指针={t[ip_key]}")
                        break
            for t in threads[:20]:
                ip_key = 'rip' if arch_bits == 64 else 'eip'
                ip_str = t.get(ip_key, 'N/A')
                tc = '◀ 崩溃' if exc and t['thread_id'] == exc['thread_id'] else ''
                report.append(f"  TID {t['thread_id']:<8d} {ip_str}  {tc}")
            if len(threads) > 20:
                report.append(f"  ... 还有 {len(threads) - 20} 个线程")
            report.append("")
        except: pass
    
    report.append("━" * 44)
    report.append("【数据流清单】")
    for st, info in sorted(streams.items()):
        tn = STREAM_TYPES.get(st, f'Unknown({st})')
        report.append(f"  {tn:<30s} {format_size(info['size'])}")
    report.append("")
    
    strings_data = extract_strings(filepath)
    report.append("━" * 44)
    report.append("【分析建议】")
    report.append("  建议使用 WinDbg: windbg -z file.dmp → !analyze -v")
    
    return '\n'.join(report)


def parse(filepath):
    fsize = os.path.getsize(filepath)
    f = open(filepath, 'rb')
    sig = f.read(8)
    if sig[:4] == MINIDUMP_SIGNATURE:
        result = parse_minidump(f, fsize, filepath)
    else:
        f.close()
        result = parse_full_dump(filepath, fsize)
    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'usage: dmp_parser.py <file.dmp>'}, ensure_ascii=False))
        sys.exit(1)
    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        print(json.dumps({'error': f'文件不存在: {filepath}'}, ensure_ascii=False))
        sys.exit(1)
    try:
        text = parse(filepath)
        print(json.dumps({'format': 'dump', 'text': text}, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({'error': str(e)}, ensure_ascii=False))
