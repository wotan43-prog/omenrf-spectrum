import os, re, signal, subprocess, threading, time
from collections import Counter, deque
from pathlib import Path

CHANNEL_FREQ = {**{ch: 2407 + ch * 5 for ch in range(1, 14)},
                **{ch: 5000 + ch * 5 for ch in (36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165)}}
CENTERS_80 = {**{ch:5210 for ch in (36,40,44,48)}, **{ch:5290 for ch in (52,56,60,64)},
              **{ch:5530 for ch in (100,104,108,112)}, **{ch:5610 for ch in (116,120,124,128)},
              **{ch:5690 for ch in (132,136,140,144)}, **{ch:5775 for ch in (149,153,157,161)}}

class PacketRadio:
    def __init__(self, root: Path):
        self.root=root; self.iface=os.environ.get('CAPTURE_INTERFACE','wlan1')
        self.scan_iface=os.environ.get('SCAN_INTERFACE','wlan0')
        self.lock=threading.Lock(); self.running=True; self.proc=None; self.record_proc=None
        self.times=deque(maxlen=10000); self.types=Counter(); self.total=0; self.channel=6; self.width=20
        self.last_rssi=None; self.error=None; self.aps={}; self.devices={}; self.discovery=[]; self.recording=None
        threading.Thread(target=self._worker,daemon=True).start()

    def _kind(self,line):
        for key,label in [('Beacon','beacon'),('Probe Request','probe_request'),('Probe Response','probe_response'),
                          ('Acknowledgment','ack'),('Block Ack','block_ack'),('QoS Data','qos_data'),('Data','data'),
                          ('Authentication','auth'),('DeAuthentication','deauth'),('Association Request','assoc')]:
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

    def state(self):
        now=time.time()
        with self.lock:
            while self.times and self.times[0] < now-10: self.times.popleft()
            fps=sum(t>=now-1 for t in self.times)
            return {'interface':self.iface,'channel':self.channel,'width':self.width,'fps':fps,'total':self.total,
                    'types':dict(self.types),'rssi':self.last_rssi,'error':self.error,'recording':self.recording,
                    'aps':sorted(self.aps.values(),key=lambda x:x['frames'],reverse=True)[:20],'discovery':self.discovery[:30]}

    def wireless_snapshot(self):
        with self.lock:
            devices={mac:{**device,'roles':list(device['roles'])} for mac,device in self.devices.items()}
            for mac,ap in self.aps.items():
                device=devices.setdefault(mac,{'mac':mac,'frames':0,'rssi':None,'roles':['BSSID'],'last_seen':None})
                device['ssid']=ap.get('ssid'); device['bssid']=mac
                if ap.get('rssi') is not None: device['rssi']=ap['rssi']
            return list(devices.values())

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
            self.record_proc.send_signal(signal.SIGINT); self.record_proc.wait(timeout=5); self.record_proc=None; self.recording=None
        else:
            name=f"wifi-{time.strftime('%Y%m%d-%H%M%S')}-ch{self.channel}.pcap"
            path=self.root/'recordings'/name
            self.record_proc=subprocess.Popen(['tcpdump','-U','-i',self.iface,'-s','0','-w',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.recording=name
        return self.state()

    def scan(self):
        out=subprocess.run(['iw','dev',self.scan_iface,'scan'],capture_output=True,text=True,timeout=20,check=True).stdout
        found=[]; cur=None
        for line in out.splitlines():
            m=re.match(r'BSS ([0-9a-f:]{17})',line.strip(),re.I)
            if m:
                if cur: found.append(cur)
                cur={'bssid':m.group(1).lower(),'ssid':'','signal':None,'freq':None}
            elif cur:
                s=line.strip()
                if s.startswith('SSID:'): cur['ssid']=s[5:].strip()
                elif s.startswith('signal:'): cur['signal']=float(s.split()[1])
                elif s.startswith('freq:'): cur['freq']=int(float(s.split()[1]))
        if cur: found.append(cur)
        self.discovery=sorted(found,key=lambda x:x['signal'] or -999,reverse=True)
        return self.discovery
