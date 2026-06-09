"""DMP dump parser."""
from pathlib import Path
import struct, re

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
