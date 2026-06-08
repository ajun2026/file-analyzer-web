#!/usr/bin/env python3
"""evtx 解析器 — 轻量快速版"""
import sys, re, json
from datetime import datetime, timedelta
from Evtx.Evtx import Evtx

HW_KW = ['nvidia','nvlddmkm','display','graphics','gpu','video','disk','storage','classpnp',
    'storport','nvme','sata','scsi','raid','memory','whea','cpu','processor',
    'kernel-power','kernel-pnp','kernel-boot','kernel-whea','pci','usb','bluetooth',
    'audio','thermal','temperature','fan','driver','crash','bugcheck','watchdog',
    'dxgk','dxdiag','ntfs','refs','bitlocker','network','ndis','firmware','bios','aqnic','marvell','aquantia','e1d','e2f','e1r','ixgbe','i40e','mlx','tg3','bnx2','enic','vmxnet','netkvm','rtl8168','rtl8125']
IMP_EIDS = {41,1001,6008,7,11,51,55,137,140,200,4101,507,908,219,1000,1002,1060,7000,7011,7031,7034}

def is_hw(ev):
    if ev['event_id'] in IMP_EIDS: return True
    txt = f"{ev['provider'].lower()} {ev.get('message','').lower()}"
    return any(kw in txt for kw in HW_KW)

def parse(path, max_scan=2000):
    events, skipped = [], 0
    with Evtx(path) as log:
        for i, rec in enumerate(log.records()):
            if i >= max_scan: break
            try:
                xml = rec.xml()
            except:
                skipped += 1; continue
            
            m = re.search(r'<TimeCreated SystemTime="([^"]+)"', xml)
            if not m: continue
            try:
                ts = datetime.strptime(m.group(1)[:19].replace('T',' '), '%Y-%m-%d %H:%M:%S')
            except: continue
            
            eid_m = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
            lv_m = re.search(r'<Level>(\d+)</Level>', xml)
            prov_m = re.search(r'Provider Name="([^"]+)"', xml)
            ch_m = re.search(r'<Channel>([^<]+)</Channel>', xml)
            
            # Data fields
            datas = {}
            for dm in re.finditer(r'<Data Name="([^"]+)">([^<]*)</Data>', xml):
                datas[dm.group(1)] = dm.group(2)
            
            # Message
            msg_m = re.search(r'<Message>(.*?)</Message>', xml, re.DOTALL)
            message = ''
            if msg_m:
                message = re.sub(r'<[^>]+>', '', msg_m.group(1)).strip()[:400]
            
            ev = {
                'ts': ts, 'time': m.group(1)[:19],
                'event_id': int(eid_m.group(1)) if eid_m else 0,
                'level': int(lv_m.group(1)) if lv_m else 0,
                'provider': prov_m.group(1) if prov_m else '',
                'channel': ch_m.group(1) if ch_m else '',
                'hardware': False, 'message': message,
            }
            if datas: ev['data'] = datas
            ev['hardware'] = is_hw(ev)
            events.append(ev)
    
    # 分类
    hw_c = [e for e in events if e['hardware'] and e['level']<=3]
    ot_c = [e for e in events if not e['hardware'] and e['level']<=3]
    norm = [e for e in events if e['level']>3]
    for lst in [hw_c, ot_c, norm]:
        lst.sort(key=lambda e: e['ts'], reverse=True)
    
    sel = hw_c[:200] + ot_c[:80] + norm[:30]
    return sel, len(events), skipped, len(hw_c), len(ot_c)

def fmt(events, total, skipped, hw, ot):
    LV = {1:'CRIT',2:'ERROR',3:'WARN',4:'INFO',5:'VERB'}
    lines = [f"扫描 {total} 条事件 | 🔧硬件/驱动错误: {hw} | 其他错误: {ot} | 展示: {len(events)}"]
    lines.append("="*55)
    cur = ''
    for ev in events:
        d = ev['ts'].strftime('%Y-%m-%d')
        if d != cur:
            cur = d; lines.append(f"\n── {d} " + "─"*43)
        lv = LV.get(ev['level'], f'Lv{ev["level"]}')
        hw = '🔧' if ev['hardware'] else '  '
        mk = '⚡' if ev['level']<=2 else ('⚠' if ev['level']==3 else '  ')
        lines.append(f"{hw}{mk} [{ev['time']}] {lv:5s} | EID={ev['event_id']:<5d} | {ev['provider']}")
        if 'data' in ev:
            for k,v in list(ev['data'].items())[:3]:
                if len(str(v))<200: lines.append(f"          {k}: {v}")
        if ev.get('message'):
            lines.append(f"          {ev['message'][:300]}")
        lines.append('')
    return '\n'.join(lines)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(json.dumps({'error':'usage'})); sys.exit(1)
    path = sys.argv[1]
    try:
        sel, total, sk, hw, ot = parse(path)
        text = fmt(sel, total, sk, hw, ot)
        print(json.dumps({
            'in_range':total, 'skipped':sk,
            'hardware_errors':hw, 'other_errors':ot,
            'shown':len(sel), 'months':0, 'text':text
        }, ensure_ascii=False))
    except Exception as e:
        print(json.dumps({'error':str(e)}))
