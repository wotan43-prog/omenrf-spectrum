#!/usr/bin/env python3
import json, os, re, signal, subprocess, threading, time
from collections import deque
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse
from capture import PacketRadio
from network_scan import NetworkScanner

ROOT=Path(__file__).resolve().parent; WEB=ROOT/'web'
SPECTOOL=Path(os.environ.get('SPECTOOL_RAW', str(Path.home()/'spectools/spectool_raw')))
state={'band':0,'running':True,'recording':False,'latest':None,'ranges':[],'error':None}
history=deque(maxlen=600); lock=threading.Lock(); proc=None
radio=None
network_scanner=None

def ranges():
    out=subprocess.check_output([str(SPECTOOL),'-l'],text=True,stderr=subprocess.DEVNULL)
    ans=[]
    rx=re.compile(r'Range (\d+): "([^"]+)" (\d+)MHz-(\d+)MHz @ ([\d.]+)([MK])Hz, (\d+) samples')
    for line in out.splitlines():
        m=rx.search(line)
        if m:
            step=float(m[5])*(1000 if m[6]=='M' else 1)
            ans.append({'id':int(m[1]),'name':m[2],'start_mhz':int(m[3]),'end_mhz':int(m[4]),'step_khz':step,'samples':int(m[7])})
    return ans

def worker():
    global proc
    while state['running']:
        band=state['band']
        try:
            proc=subprocess.Popen(['stdbuf','-oL',str(SPECTOOL),'-r',str(band)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
            prefix='Wi-Spy DBx USB '
            for line in proc.stdout:
                if band!=state['band'] or not state['running']: break
                if not line.startswith(prefix) or ':' not in line: continue
                try: values=[int(x) for x in line.split(':',1)[1].split()]
                except ValueError: continue
                r=state['ranges'][band]
                sweep={'ts':time.time(),'band':band,'start_mhz':r['start_mhz'],'end_mhz':r['end_mhz'],'values':values}
                with lock:
                    state['latest']=sweep; history.append(sweep); state['error']=None
                if state['recording']:
                    with open(ROOT/'recordings'/f"capture-{time.strftime('%Y%m%d')}.jsonl",'a') as f: f.write(json.dumps(sweep)+'\n')
            proc.terminate(); proc.wait(timeout=2)
        except Exception as e:
            state['error']=str(e); time.sleep(1)

class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*a,**k): super().__init__(*a,directory=str(WEB),**k)
    def log_message(self,*a): pass
    def json(self,obj,status=200):
        data=json.dumps(obj).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def json_body(self):
        try: length=int(self.headers.get('Content-Length','0'))
        except ValueError: raise ValueError('invalid content length')
        if length<1 or length>4096: raise ValueError('JSON body must be between 1 and 4096 bytes')
        try: return json.loads(self.rfile.read(length))
        except json.JSONDecodeError as e: raise ValueError('invalid JSON body') from e
    def do_GET(self):
        p=urlparse(self.path).path
        if p=='/api/state':
            with lock: self.json({'band':state['band'],'recording':state['recording'],'ranges':state['ranges'],'latest':state['latest'],'error':state['error']}); return
        if p=='/api/capture/state': self.json(radio.state()); return
        if p=='/api/nmap/state': self.json(network_scanner.state()); return
        if p.startswith('/api/recordings/'):
            name=Path(p).name; target=(ROOT/'recordings'/name).resolve()
            if target.parent != (ROOT/'recordings').resolve() or not target.exists(): return self.json({'error':'not found'},404)
            content_type='application/json' if target.suffix=='.json' else 'application/vnd.tcpdump.pcap'
            data=target.read_bytes(); self.send_response(200); self.send_header('Content-Type',content_type); self.send_header('Content-Disposition',f'attachment; filename="{name}"'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data); return
        super().do_GET()
    def do_POST(self):
        global proc
        p=urlparse(self.path).path
        if p.startswith('/api/band/'):
            n=int(p.rsplit('/',1)[1]);
            if n<0 or n>=len(state['ranges']): return self.json({'error':'invalid band'},400)
            state['band']=n
            if proc: proc.terminate()
            return self.json({'ok':True,'band':n})
        if p=='/api/record': state['recording']=not state['recording']; return self.json({'ok':True,'recording':state['recording']})
        if p=='/api/reset':
            with lock: history.clear()
            return self.json({'ok':True})
        if p.startswith('/api/capture/tune/'):
            try:
                _,ch,width=p.rsplit('/',2); return self.json(radio.tune(int(ch),int(width)))
            except Exception as e: return self.json({'error':str(e)},400)
        if p=='/api/capture/record':
            try: return self.json(radio.toggle_recording())
            except Exception as e: return self.json({'error':str(e)},500)
        if p=='/api/capture/scan':
            try: return self.json({'results':radio.scan()})
            except Exception as e: return self.json({'error':str(e)},500)
        if p=='/api/nmap/run':
            try:
                body=self.json_body()
                return self.json({'ok':True,'job':network_scanner.start(body.get('profile'),body.get('target'))},202)
            except RuntimeError as e: return self.json({'error':str(e)},409)
            except Exception as e: return self.json({'error':str(e)},400)
        self.json({'error':'not found'},404)

if __name__=='__main__':
    (ROOT/'recordings').mkdir(exist_ok=True); state['ranges']=ranges(); radio=PacketRadio(ROOT)
    network_scanner=NetworkScanner(ROOT,radio.wireless_snapshot)
    if not state['ranges']: raise SystemExit('No DBx3 sweep ranges found')
    threading.Thread(target=worker,daemon=True).start()
    host=os.environ.get('OMENRF_HOST','0.0.0.0'); port=int(os.environ.get('OMENRF_PORT','8765'))
    try: ThreadingHTTPServer((host,port),Handler).serve_forever()
    finally:
        state['running']=False
        if proc: proc.terminate()
