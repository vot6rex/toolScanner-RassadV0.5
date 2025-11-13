#!/usr/bin/env python3
"""
by_votrex6_gui.py
BY VO@TREX6 - Analyzer PRO (GUI single-file)

Features:
 - PyQt5 GUI (fallback to Tkinter)
 - Asyncio-based scanner running in background thread
 - TCP connect banner grab, optional UDP, optional TLS probe (in executor)
 - CIDR/range/targets file support, resume autosave, JSON/CSV save
 - Start/Stop, progress, results table
"""

import sys, os, threading, asyncio, time, json, ssl, socket, csv, ipaddress, re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

# ---------- optional color (console) ----------
try:
    from colorama import init as _color_init, Fore, Style
    _color_init()
    def c(s): return Fore.CYAN + s + Style.RESET_ALL
except Exception:
    def c(s): return s

# ---------- try PyQt5, else fallback to Tkinter ----------
USE_PYQT = False
try:
    from PyQt5.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
        QProgressBar, QTableWidget, QTableWidgetItem, QFileDialog, QCheckBox, QSpinBox, QMessageBox
    )
    from PyQt5.QtCore import QTimer
    USE_PYQT = True
except Exception:
    USE_PYQT = False
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

# ---------- scanner core (async) ----------
# reuse simplified safe probe functions (async TCP connect + optional TLS via executor, UDP)
FINGERPRINT_RULES = [
    (re.compile(r"^HTTP/1\.[01] \d{3}"), "HTTP"),
    (re.compile(r"^Server:\s*(.+)", re.I), "HTTP-Server"),
    (re.compile(r"^SSH-([0-9.]+)-(.+)$", re.I), "SSH"),
    (re.compile(r"^220 .*ESMTP", re.I), "SMTP"),
]

def fingerprint_banner(b: str):
    if not b: return None
    for ln in b.splitlines()[:5]:
        for pat,name in FINGERPRINT_RULES:
            m = pat.search(ln.strip())
            if m:
                return name
    return None

async def tcp_probe(target: str, port: int, timeout: float, tls: bool, tls_all: bool, loop):
    out = {'target':target,'port':port,'proto':'tcp','open':False,'banner':'','finger':None,'tls_cert':None}
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host=target, port=port), timeout=timeout)
        out['open'] = True
        # TLS probe if requested and port common
        if tls and (tls_all or port in (443,8443,9443)):
            try:
                cert = await loop.run_in_executor(None, fetch_cert_blocking, target, port, max(1.0, timeout))
                out['tls_cert'] = cert
            except Exception:
                out['tls_cert'] = None
        # probe banner
        probe = b'HEAD / HTTP/1.0\r\n\r\n'
        try:
            writer.write(probe)
            await writer.drain()
        except Exception:
            pass
        try:
            data = await asyncio.wait_for(reader.read(2048), timeout=min(1.0, timeout))
            if data:
                text = data.decode(errors='ignore').strip()
                out['banner'] = text
                out['finger'] = fingerprint_banner(text)
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        pass
    return out

# blocking TLS cert fetch for executor
def fetch_cert_blocking(host: str, port:int=443, timeout:float=3.0):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None

class AsyncScanner:
    def __init__(self, cfg):
        self.cfg = cfg
        self.loop = None
        self.thread = None
        self._stop = threading.Event()
        self.results: List[Dict[str,Any]] = []
        self.done: Set[str] = set()
        self.lock = threading.Lock()
        self.total = 0
        self.completed = 0
        self.start_ts = None

    def load_resume(self):
        if os.path.exists(self.cfg['resume']):
            try:
                with open(self.cfg['resume'],'r') as f:
                    arr = json.load(f)
                    if isinstance(arr, list):
                        self.done = set(arr)
            except Exception:
                pass

    def save_resume(self):
        try:
            with open(self.cfg['resume'],'w') as f:
                json.dump(sorted(list(self.done)), f)
        except Exception:
            pass

    def start(self, targets, ports):
        # spawn thread running asyncio loop
        self._stop.clear()
        self.results = []
        self.start_ts = time.time()
        self.completed = 0
        # compute total
        self.total = len(targets) * len(ports) * (1 + (1 if self.cfg['udp'] else 0))
        self.load_resume()
        self.thread = threading.Thread(target=self._run_loop, args=(targets, ports), daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()
        # stop loop
        if self.loop:
            try:
                self.loop.call_soon_threadsafe(self.loop.stop)
            except Exception:
                pass

    def _record(self, r):
        with self.lock:
            self.results.append(r)
            self.done.add(f"{r['target']}:{r['port']}/{r['proto']}")
            self.completed += 1
            if time.time() - getattr(self,'last_save',0) > self.cfg.get('autosave',5):
                self.save_resume()
                self.last_save = time.time()

    def _run_loop(self, targets, ports):
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self._scan_all(targets, ports))
        except Exception as e:
            print("Scanner thread exception:", e)
        finally:
            try:
                self.save_resume()
            except Exception:
                pass
            self.loop = None

    async def _scan_all(self, targets, ports):
        sem = asyncio.Semaphore(self.cfg['threads'])
        loop = asyncio.get_event_loop()
        tasks = []
        for t in targets:
            # optional ping
            if self.cfg['ping']:
                alive = await system_ping(t, self.cfg['timeout_ms'])
                if not alive:
                    continue
            for p in ports:
                if self._stop.is_set():
                    return
                await sem.acquire()
                tasks.append(asyncio.create_task(self._handle_one(t,p,sem,loop)))
        if tasks:
            await asyncio.gather(*tasks)

    async def _handle_one(self, target, port, sem, loop):
        try:
            # tcp
            if self._stop.is_set(): return
            tcpk = f"{target}:{port}/tcp"
            if tcpk not in self.done:
                tcp = await tcp_probe(target, port, self.cfg['timeout'], self.cfg['tls'], self.cfg['tls_all'], loop)
                self._record(tcp)
            # udp
            if self.cfg['udp']:
                if self._stop.is_set(): return
                udpk = f"{target}:{port}/udp"
                if udpk not in self.done:
                    udp = await udp_probe_simple(target, port, self.cfg['timeout'], loop)
                    self._record(udp)
        finally:
            sem.release()

# simple UDP probe using blocking socket in executor for reliability
async def udp_probe_simple(target, port, timeout, loop):
    def blocking_udp():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.sendto(b'votre_probe', (target, port))
                data, addr = s.recvfrom(2048)
                txt = data.decode(errors='ignore').strip()
                return {'target':target,'port':port,'proto':'udp','open':True,'banner':txt,'finger':fingerprint_banner(txt)}
            except Exception:
                return {'target':target,'port':port,'proto':'udp','open':False,'banner':'','finger':None}
            finally:
                s.close()
        except Exception:
            return {'target':target,'port':port,'proto':'udp','open':False,'banner':'','finger':None}
    return await loop.run_in_executor(None, blocking_udp)

# system ping fallback
async def system_ping(host, timeout_ms):
    timeout_s = max(1, int(max(1, timeout_ms/1000)))
    if sys.platform.startswith('win'):
        cmd = ['ping','-n','1','-w',str(timeout_ms),host]
    else:
        cmd = ['ping','-c','1','-W',str(timeout_s),host]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    try:
        await asyncio.wait_for(proc.communicate(), timeout=timeout_s+2)
    except Exception:
        proc.kill()
        return False
    return proc.returncode == 0

# ---------- GUI: PyQt5 implementation ----------
if USE_PYQT:
    class MainWin(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("BY VO@TREX6 - Analyzer PRO (GUI)")
            self.setGeometry(200,200,1000,600)
            self.cfg = {
                'threads':200,'timeout':0.6,'timeout_ms':600,'retries':1,'retry_delay':0.2,
                'udp':False,'tls':False,'tls_all':False,'syn':False,'autosave':5,'rate':0.0,'ping':False
            }
            self.scanner: Optional[AsyncScanner] = None
            self._build_ui()
            self.timer = QTimer()
            self.timer.setInterval(800)
            self.timer.timeout.connect(self._tick)

        def _build_ui(self):
            v = QVBoxLayout()
            h1 = QHBoxLayout()
            self.targets_edit = QLineEdit()
            self.targets_edit.setPlaceholderText("Targets (comma or CIDR or ranges) e.g. 127.0.0.1,192.168.1.0/28")
            h1.addWidget(QLabel("Targets:"))
            h1.addWidget(self.targets_edit)
            v.addLayout(h1)

            h2 = QHBoxLayout()
            self.ports_edit = QLineEdit("1-1024")
            h2.addWidget(QLabel("Ports:"))
            h2.addWidget(self.ports_edit)
            v.addLayout(h2)

            opts = QHBoxLayout()
            self.udp_cb = QCheckBox("UDP")
            self.tls_cb = QCheckBox("TLS")
            self.ping_cb = QCheckBox("Ping before scan")
            self.udp_cb.stateChanged.connect(lambda _: None)
            opts.addWidget(self.udp_cb); opts.addWidget(self.tls_cb); opts.addWidget(self.ping_cb)
            v.addLayout(opts)

            h3 = QHBoxLayout()
            self.threads_spin = QSpinBox(); self.threads_spin.setRange(1,2000); self.threads_spin.setValue(200)
            self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(100,10000); self.timeout_spin.setValue(600)
            h3.addWidget(QLabel("Concurrency:")); h3.addWidget(self.threads_spin)
            h3.addWidget(QLabel("Timeout ms:")); h3.addWidget(self.timeout_spin)
            v.addLayout(h3)

            btns = QHBoxLayout()
            self.start_btn = QPushButton("Start")
            self.stop_btn = QPushButton("Stop"); self.stop_btn.setEnabled(False)
            self.save_btn = QPushButton("Save JSON")
            btns.addWidget(self.start_btn); btns.addWidget(self.stop_btn); btns.addWidget(self.save_btn)
            v.addLayout(btns)

            self.progress = QProgressBar(); self.progress.setValue(0)
            v.addWidget(self.progress)
            self.status_label = QLabel("Ready")
            v.addWidget(self.status_label)

            self.table = QTableWidget(0,5)
            self.table.setHorizontalHeaderLabels(["Proto","Target","Port","Open","Banner"])
            v.addWidget(self.table)

            self.setLayout(v)

            # signals
            self.start_btn.clicked.connect(self.on_start)
            self.stop_btn.clicked.connect(self.on_stop)
            self.save_btn.clicked.connect(self.on_save)

        def append_row(self, r: Dict[str,Any]):
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row,0, QTableWidgetItem(r.get('proto','')))
            self.table.setItem(row,1, QTableWidgetItem(r.get('target','')))
            self.table.setItem(row,2, QTableWidgetItem(str(r.get('port',''))))
            self.table.setItem(row,3, QTableWidgetItem(str(r.get('open'))))
            self.table.setItem(row,4, QTableWidgetItem((r.get('banner') or '')[:200]))

        def on_start(self):
            text = self.targets_edit.text().strip()
            if not text:
                QMessageBox.warning(self, "No targets", "Provide at least one target or CIDR")
                return
            targets = [x.strip() for x in re.split(r'[,\s]+', text) if x.strip()]
            ports_str = self.ports_edit.text().strip()
            try:
                ports = parse_ports(ports_str)
            except Exception:
                QMessageBox.warning(self, "Ports", "Invalid ports")
                return
            cfg = {
                'threads': self.threads_spin.value(),
                'timeout': self.timeout_spin.value()/1000.0,
                'timeout_ms': self.timeout_spin.value(),
                'udp': self.udp_cb.isChecked(),
                'tls': self.tls_cb.isChecked(),
                'tls_all': False,
                'syn': False,
                'autosave':5,
                'partial':'partial_results.json',
                'resume':'votre_resume.json',
                'rate':0.0,
                'ping': self.ping_cb.isChecked()
            }
            self.cfg = cfg
            # expand targets
            targets = expand_targets(targets)
            # reset table/results
            self.table.setRowCount(0)
            self.scanner = AsyncScanner(cfg)
            self.scanner.start(targets, ports)
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            self.timer.start()
            self.status_label.setText("Scanning...")

        def on_stop(self):
            if self.scanner:
                self.scanner.stop()
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            self.timer.stop()
            self.status_label.setText("Stopped")

        def on_save(self):
            if not self.scanner:
                QMessageBox.information(self, "No data", "No scan data to save")
                return
            fname, _ = QFileDialog.getSaveFileName(self, "Save JSON", "scan_results.json", "JSON Files (*.json)")
            if fname:
                with open(fname,'w') as f:
                    json.dump(self.scanner.results, f, indent=2)
                QMessageBox.information(self, "Saved", f"Saved to {fname}")

        def _tick(self):
            if not self.scanner:
                return
            # drain results
            with self.scanner.lock:
                new = list(self.scanner.results)
                self.scanner.results = []
            for r in new:
                self.append_row(r)
            # update progress
            if self.scanner.total>0:
                pct = int((self.scanner.completed/self.scanner.total)*100)
            else:
                pct = 0
            self.progress.setValue(pct)
            self.status_label.setText(f"Done {self.scanner.completed}/{self.scanner.total}")

    def main_pyqt():
        app = QApplication(sys.argv)
        w = MainWin()
        w.show()
        sys.exit(app.exec_())

# ---------- Tkinter fallback ----------
else:
    class TkMain:
        def __init__(self, root):
            self.root = root
            root.title("BY VO@TREX6 - Analyzer PRO (GUI Tk)")
            self.cfg = {'threads':200,'timeout':0.6,'timeout_ms':600,'udp':False,'tls':False,'autosave':5,'resume':'votre_resume.json','partial':'partial_results.json','rate':0.0,'ping':False}
            self.scanner = None
            self._build()

        def _build(self):
            frm = ttk.Frame(self.root); frm.pack(fill='both', expand=True, padx=8,pady=8)
            ttk.Label(frm, text="Targets (comma/CIDR):").pack(anchor='w')
            self.targets_ent = ttk.Entry(frm, width=80); self.targets_ent.pack(fill='x')
            ttk.Label(frm, text="Ports (e.g. 1-1024 or 22,80,443):").pack(anchor='w')
            self.ports_ent = ttk.Entry(frm, width=40); self.ports_ent.insert(0,"1-1024"); self.ports_ent.pack()
            opts = ttk.Frame(frm); opts.pack(fill='x', pady=4)
            self.udp_var = tk.BooleanVar(); ttk.Checkbutton(opts, text='UDP', variable=self.udp_var).pack(side='left')
            self.tls_var = tk.BooleanVar(); ttk.Checkbutton(opts, text='TLS', variable=self.tls_var).pack(side='left')
            self.ping_var = tk.BooleanVar(); ttk.Checkbutton(opts, text='Ping before', variable=self.ping_var).pack(side='left')
            ctl = ttk.Frame(frm); ctl.pack(fill='x', pady=4)
            ttk.Button(ctl, text="Start", command=self.on_start).pack(side='left')
            ttk.Button(ctl, text="Stop", command=self.on_stop).pack(side='left')
            ttk.Button(ctl, text="Save JSON", command=self.on_save).pack(side='left')
            self.progress = ttk.Progressbar(frm, length=400); self.progress.pack(pady=6)
            self.status = ttk.Label(frm, text="Ready"); self.status.pack()
            self.table = ttk.Treeview(frm, columns=('proto','target','port','open','banner'), show='headings')
            for c in ('proto','target','port','open','banner'):
                self.table.heading(c, text=c)
            self.table.pack(fill='both', expand=True)

        def on_start(self):
            text = self.targets_ent.get().strip()
            if not text:
                messagebox.showwarning("No targets","Provide target(s)")
                return
            targets = [x.strip() for x in re.split(r'[,\s]+', text) if x.strip()]
            ports = parse_ports(self.ports_ent.get())
            cfg = {'threads':200,'timeout':self.cfg['timeout'],'timeout_ms':self.cfg['timeout_ms'],'udp':self.udp_var.get(),'tls':self.tls_var.get(),'autosave':5,'resume':'votre_resume.json','partial':'partial_results.json','rate':0.0,'ping':self.ping_var.get()}
            self.scanner = AsyncScanner(cfg)
            self.scanner.start(expand_targets(targets), ports)
            self.root.after(500, self._tick)
            self.status.config(text="Scanning...")

        def on_stop(self):
            if self.scanner: self.scanner.stop(); self.status.config(text="Stopped")

        def on_save(self):
            if not self.scanner:
                messagebox.showinfo("No data","No scan data")
                return
            fname = filedialog.asksaveasfilename(defaultextension=".json")
            if fname:
                with open(fname,'w') as f: json.dump(self.scanner.results, f, indent=2)
                messagebox.showinfo("Saved", f"Saved to {fname}")

        def _tick(self):
            if not self.scanner:
                return
            with self.scanner.lock:
                new = list(self.scanner.results); self.scanner.results=[]
            for r in new:
                self.table.insert('', 'end', values=(r.get('proto'), r.get('target'), r.get('port'), r.get('open'), (r.get('banner') or '')[:200]))
            total = self.scanner.total or 1
            pct = int((self.scanner.completed/total)*100 if total else 0)
            self.progress['value'] = pct
            self.status.config(text=f"Done {self.scanner.completed}/{self.scanner.total}")
            self.root.after(800, self._tick)

    def main_tk():
        root = tk.Tk()
        app = TkMain(root)
        root.mainloop()

# ---------- helpers shared ----------
def parse_ports(s: str) -> List[int]:
    s = s.strip()
    parts = [p.strip() for p in s.split(',') if p.strip()]
    out = set()
    for p in parts:
        if '-' in p:
            a,b = p.split('-',1)
            out.update(range(int(a), int(b)+1))
        else:
            out.add(int(p))
    return sorted([x for x in out if 1 <= x <= 65535])

def expand_targets(items: List[str]) -> List[str]:
    out=[]
    for it in items:
        it = it.strip()
        if not it: continue
        if '/' in it:
            try:
                net = ipaddress.ip_network(it, strict=False)
                for ip in net.hosts(): out.append(str(ip))
                continue
            except Exception:
                continue
        if '-' in it and it.count('.')==3:
            left,right=it.split('-',1)
            try:
                if right.count('.')==3:
                    start=ipaddress.IPv4Address(left); end=ipaddress.IPv4Address(right)
                else:
                    base='.'.join(left.split('.')[:-1])
                    start=ipaddress.IPv4Address(left); end=ipaddress.IPv4Address(base + '.' + right)
                for i in range(int(start), int(end)+1): out.append(str(ipaddress.IPv4Address(i)))
                continue
            except Exception:
                continue
        out.append(it)
    return out

# ---------- entrypoint ----------
def main():
    if USE_PYQT:
        main_pyqt()
    else:
        main_tk()

if __name__ == '__main__':
    main()
