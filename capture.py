import os, re, signal, subprocess, threading, time
from collections import Counter, deque
from pathlib import Path

CHANNEL_FREQ = {**{ch: 2407 + ch * 5 for ch in range(1, 14)},
                **{ch: 5000 + ch * 5 for ch in (36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165)}}
CENTERS_80 = {**{ch:5210 for ch in (36,40,44,48)}, **{ch:5290 for ch in (52,56,60,64)},
              **{ch:5530 for ch in (100,104,108,112)}, **{ch:5610 for ch in (116,120,124,128)},
              **{ch:5690 for ch in (132,136,140,144)}, **{ch:5775 for ch in (149,153,157,161)}}

FRAME_KINDS = (
    ('Beacon', 'beacon'), ('Probe Request', 'probe_request'), ('Probe Response', 'probe_response'),
    ('Acknowledgment', 'ack'), ('Block Ack', 'block_ack'), ('QoS Data', 'qos_data'),
    ('Data', 'data'), ('Authentication', 'auth'), ('DeAuthentication', 'deauth'),
    ('Association Request', 'assoc'),
)

AP_NAME_FIELDS = (
    ('wlan.vs.aruba.ap_name', 'Aruba'),
    ('wlan.vs.extreme.ap_name', 'Extreme'),
    ('wlan.vs.mist.apname', 'Mist'),
    ('wlan.vs.ruckus.apname', 'Ruckus'),
    ('wlan.vs.alcatel.apname', 'Alcatel-Lucent'),
    ('wlan.vs.fortinet.system.ap_name', 'Fortinet'),
    ('wlan.vs.arista.ap_name', 'Arista'),
    ('wps.device_name', 'WPS'),
)

def parse_ap_identity_row(line):
    parts=line.rstrip('\n').split('\t')
    if not parts or not re.fullmatch(r'[0-9a-f:]{17}', parts[0], re.I): return None
    values=(parts[1:] + [''] * len(AP_NAME_FIELDS))[:len(AP_NAME_FIELDS)]
    for (_, source), value in zip(AP_NAME_FIELDS, values):
        value=value.strip().strip('\"')
        if value and value != '<MISSING>':
            return {'bssid':parts[0].lower(),'ap_name':value,'ap_name_source':source}
    return None


def parse_frame_metadata(line, frame_id, channel, now=None):
    """Extract bounded 802.11 header metadata without retaining packet payload text."""
    now = now if now is not None else time.time()
    kind = next((label for key, label in FRAME_KINDS if key in line), 'other')
    rssi = re.search(r'(-\d+)dBm signal', line)
    roles = {role.upper(): mac.lower() for role, mac in re.findall(
        r'\b(RA|TA|SA|DA|BSSID):([0-9a-f:]{17})', line, re.I
    )}
    bssid = re.search(r'BSSID:([0-9a-f:]{17})', line, re.I)
    ssid = re.search(r'(?:Beacon|Probe (?:Request|Response)) \((.*?)\)', line)
    length = re.search(r'\blength (\d+)(?:\s|$)', line)
    frequency = re.search(r'\b(\d{4}) MHz\b', line)
    return {
        'id': frame_id,
        'ts': now,
        'type': kind,
        'source': roles.get('SA') or roles.get('TA'),
        'destination': roles.get('DA') or roles.get('RA'),
        'bssid': (bssid.group(1).lower() if bssid else roles.get('BSSID')),
        'ssid': ssid.group(1) if ssid else None,
        'rssi': int(rssi.group(1)) if rssi else None,
        'channel': channel,
        'frequency_mhz': int(frequency.group(1)) if frequency else None,
        'length': int(length.group(1)) if length else None,
        'roles': roles,
    }

class PacketRadio:
    def __init__(self, root: Path):
        self.root=root; self.iface=os.environ.get('CAPTURE_INTERFACE','wlan1')
        self.scan_iface=os.environ.get('SCAN_INTERFACE','wlan0')
        self.lock=threading.Lock(); self.scan_lock=threading.Lock(); self.running=True; self.proc=None; self.record_proc=None
        self.times=deque(maxlen=10000); self.frames=deque(maxlen=1000); self.frame_id=0
        self.types=Counter(); self.total=0; self.channel=6; self.width=20
        self.last_rssi=None; self.error=None; self.aps={}; self.devices={}; self.discovery=[]; self.scan_error=None; self.scan_time=None; self.recording=None
        self.ap_identities={}
        self.recording_path=None; self.recording_started=None
        threading.Thread(target=self._worker,daemon=True).start()
        threading.Thread(target=self._identity_worker,daemon=True).start()

    def _kind(self,line):
        for key,label in FRAME_KINDS:
            if key in line: return label
        return 'other'

    def _worker(self):
        while self.running:
            try:
                self.proc=subprocess.Popen(['tcpdump','-l','-n','-e','-s','256','-i',self.iface],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                for line in self.proc.stdout:
                    now=time.time(); kind=self._kind(line)
                    rssi=re.search(r'(-\d+)dBm signal',line); bssid=re.search(r'BSSID:([0-9a-f:]{17})',line,re.I)
                    mac_hits=re.findall(r'\b(RA|TA|SA|DA|BSSID):([0-9a-f:]{17})',line,re.I)
                    ssid=re.search(r'Beacon \((.*?)\)',line)
                    with self.lock:
                        self.frame_id+=1
                        self.frames.append(parse_frame_metadata(line,self.frame_id,self.channel,now))
                        self.times.append(now); self.types[kind]+=1; self.total+=1; self.error=None
                        if rssi: self.last_rssi=int(rssi.group(1))
                        for role,mac_value in mac_hits:
                            mac_value=mac_value.lower(); role=role.upper()
                            device=self.devices.setdefault(mac_value,{'mac':mac_value,'frames':0,'rssi':None,'roles':[],'last_seen':now})
                            device['frames']+=1; device['last_seen']=now
                            if role not in device['roles']: device['roles'].append(role)
                            if rssi: device['rssi']=int(rssi.group(1))
                        if bssid:
                            mac=bssid.group(1).lower(); ap=self.aps.setdefault(mac,{'bssid':mac,'ssid':'','frames':0,'rssi':None})
                            ap['frames']+=1
                            if rssi: ap['rssi']=int(rssi.group(1))
                            if ssid: ap['ssid']=ssid.group(1)
                err=self.proc.stderr.read().strip()
                if self.running: self.error=err or 'packet capture stopped'
            except Exception as e: self.error=str(e)
            time.sleep(1)

    def _identity_worker(self):
        fields=[]
        for name,_ in AP_NAME_FIELDS: fields += ['-e',name]
        while self.running:
            try:
                cmd=['tshark','-l','-i',self.iface,'-a','duration:4',
                     '-Y','wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5',
                     '-T','fields','-E','separator=\t','-e','wlan.bssid',*fields]
                out=subprocess.run(cmd,capture_output=True,text=True,timeout=8,check=False).stdout
                found={}
                for line in out.splitlines():
                    item=parse_ap_identity_row(line)
                    if item: found[item['bssid']]=item
                if found:
                    with self.lock: self.ap_identities.update(found)
            except Exception:
                pass
            for _ in range(26):
                if not self.running: break
                time.sleep(1)

    def state(self):
        now=time.time()
        with self.lock:
            while self.times and self.times[0] < now-10: self.times.popleft()
            fps=sum(t>=now-1 for t in self.times)
            discovered={item.get('bssid'):item for item in self.discovery if item.get('bssid')}
            discovery=[]
            for item in self.discovery:
                merged_item=dict(item); identity=self.ap_identities.get(item.get('bssid')) or {}
                if identity:
                    merged_item['ap_name']=identity.get('ap_name') or merged_item.get('ap_name')
                    merged_item['ap_name_source']=identity.get('ap_name_source')
                discovery.append(merged_item)
            aps=[]
            for ap in self.aps.values():
                merged=dict(ap)
                identity=self.ap_identities.get(ap.get('bssid')) or {}
                match=discovered.get(ap.get('bssid')) or {}
                merged['ap_name']=identity.get('ap_name') or match.get('ap_name') or match.get('device_name')
                merged['ap_name_source']=identity.get('ap_name_source') or ('Active scan' if merged.get('ap_name') else None)
                if not merged.get('ssid'): merged['ssid']=match.get('ssid') or ''
                aps.append(merged)
            return {'interface':self.iface,'scan_interface':self.scan_iface,'channel':self.channel,'width':self.width,'fps':fps,'total':self.total,
                    'types':dict(self.types),'rssi':self.last_rssi,'error':self.error,'recording':self.recording,
                    'aps':sorted(aps,key=lambda x:x['frames'],reverse=True)[:20],
                    'discovery':discovery[:30],'scan_error':self.scan_error,'scan_time':self.scan_time}

    def wireless_snapshot(self):
        with self.lock:
            devices={mac:{**device,'roles':list(device['roles'])} for mac,device in self.devices.items()}
            discovered={item.get('bssid'):item for item in self.discovery if item.get('bssid')}
            for mac,ap in self.aps.items():
                device=devices.setdefault(mac,{'mac':mac,'frames':0,'rssi':None,'roles':['BSSID'],'last_seen':None})
                match=discovered.get(mac) or {}; identity=self.ap_identities.get(mac) or {}
                device['ssid']=ap.get('ssid') or match.get('ssid'); device['bssid']=mac
                device['ap_name']=identity.get('ap_name') or match.get('ap_name') or match.get('device_name')
                device['ap_name_source']=identity.get('ap_name_source') or ('Active scan' if device.get('ap_name') else None)
                if ap.get('rssi') is not None: device['rssi']=ap['rssi']
            return list(devices.values())

    def frame_snapshot(self, after=0, limit=100, kind=None, mac=None):
        after=max(0,int(after)); limit=max(1,min(200,int(limit)))
        kind=(kind or '').strip().lower(); mac=(mac or '').strip().lower()
        with self.lock:
            frames=[dict(frame) for frame in self.frames if frame['id']>after]
            latest=self.frame_id
        if kind: frames=[frame for frame in frames if frame['type']==kind]
        if mac:
            frames=[frame for frame in frames if mac in {
                frame.get('source'), frame.get('destination'), frame.get('bssid'),
            }]
        if after == 0:
            frames=frames[-limit:]; next_cursor=latest
        else:
            frames=frames[:limit]; next_cursor=frames[-1]['id'] if frames else latest
        return {'frames':frames,'next_cursor':next_cursor,'capacity':1000}

    def device_snapshot(self):
        devices=self.wireless_snapshot()
        return sorted(devices,key=lambda item:(item.get('last_seen') or 0,item.get('frames') or 0),reverse=True)[:200]

    def recording_files(self):
        base=(self.root/'recordings').resolve()
        with self.lock:
            try: active=str(self.recording_path.resolve().relative_to(base)) if self.recording_path else None
            except ValueError: active=None
            started=self.recording_started
        files=[]
        for path in base.rglob('*.pcap'):
            try:
                stat=path.stat(); relative=str(path.resolve().relative_to(base))
            except (OSError,ValueError):
                continue
            files.append({'path':relative,'name':path.name,'size':stat.st_size,'modified_at':stat.st_mtime,
                          'active':relative==active,'started_at':started if relative==active else None})
        return sorted(files,key=lambda item:item['modified_at'],reverse=True)[:50]

    def tune(self,ch,width=20):
        ch=int(ch); width=int(width)
        if ch not in CHANNEL_FREQ or width not in (20,40,80): raise ValueError('unsupported channel or width')
        if width==20: cmd=['iw','dev',self.iface,'set','channel',str(ch),'HT20']
        elif width==40:
            suffix='HT40-' if ch in (40,48,56,64,104,112,120,128,136,144,153,161) else 'HT40+'
            cmd=['iw','dev',self.iface,'set','channel',str(ch),suffix]
        else:
            if ch not in CENTERS_80: raise ValueError('80 MHz is not valid on this primary channel')
            cmd=['iw','dev',self.iface,'set','freq',str(CHANNEL_FREQ[ch]),'80',str(CENTERS_80[ch])]
        subprocess.run(cmd,check=True,capture_output=True,text=True); self.channel=ch; self.width=width
        return self.state()

    def toggle_recording(self):
        if self.record_proc and self.record_proc.poll() is None:
            self.stop_recording()
        else:
            name=f"wifi-{time.strftime('%Y%m%d-%H%M%S')}-ch{self.channel}.pcap"
            self.start_recording(self.root/'recordings'/name,display_name=name)
        return self.state()

    def start_recording(self,path,display_name=None):
        if self.record_proc and self.record_proc.poll() is None: raise RuntimeError('packet capture is already recording')
        path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
        self.record_proc=subprocess.Popen(['tcpdump','-U','-i',self.iface,'-s','0','-w',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.recording=display_name or path.name; self.recording_path=path; self.recording_started=time.time()
        return self.recording

    def stop_recording(self):
        if self.record_proc and self.record_proc.poll() is None:
            self.record_proc.send_signal(signal.SIGINT); self.record_proc.wait(timeout=5)
        self.record_proc=None; self.recording=None; self.recording_path=None; self.recording_started=None

    def scan(self):
        if not self.scan_lock.acquire(blocking=False): raise RuntimeError('AP discovery is already running')
        try:
            out=subprocess.run(['iw','dev',self.scan_iface,'scan'],capture_output=True,text=True,timeout=20,check=True).stdout
            found=[]; cur=None
            for line in out.splitlines():
                m=re.match(r'BSS ([0-9a-f:]{17})',line.strip(),re.I)
                if m:
                    if cur: found.append(cur)
                    cur={'bssid':m.group(1).lower(),'ssid':'','signal':None,'freq':None,'ap_name':None,'device_name':None}
                elif cur:
                    s=line.strip()
                    if s.startswith('SSID:'): cur['ssid']=s[5:].strip()
                    elif s.startswith('signal:'): cur['signal']=float(s.split()[1])
                    elif s.startswith('freq:'): cur['freq']=int(float(s.split()[1]))
                    elif 'ap name:' in s.lower():
                        cur['ap_name']=s[s.lower().index('ap name:') + len('ap name:'):].strip() or None
                    elif 'device name:' in s.lower():
                        cur['device_name']=s[s.lower().index('device name:') + len('device name:'):].strip() or None
            if cur: found.append(cur)
            with self.lock:
                self.discovery=sorted(found,key=lambda x:x['signal'] or -999,reverse=True)
                self.scan_error=None; self.scan_time=time.time()
                return list(self.discovery)
        except Exception as exc:
            with self.lock: self.scan_error=str(exc); self.scan_time=time.time()
            raise
        finally:
            self.scan_lock.release()
