# This is a professional-grade Windows activity viewer, designed for
# forensic analysis, system monitoring, and personal privacy checks.
# It provides a sleek, animated UI and extracts data from various
# Windows sources including recent files, event logs, and browser histories.
#
# Features:
# - Recent Files: Lists recently accessed documents and applications.
# - Login/Logout Events: Extracts security event logs for user sessions.
# - System Start/Shutdown: Monitors system uptime and reboots.
# - Browser History: Gathers data from Chrome, Edge, and Firefox.
# - Summary View: Provides a quick overview of key activities.
# - Export Functionality: Allows saving all gathered data to a text file.
# - Animated UI: Smooth transitions and modern aesthetics using PyQt5.
# - Robust Data Extraction: Handles locked database files gracefully.
#
# Usage:
# Run the script. The UI will guide you through the available features.
#
# Dependencies:
# - PyQt5
# - qtawesome
# - pywin32 (for win32evtlog)
#
# Installation:
# pip install PyQt5 qtawesome pywin32
#
# Author: Your Name/Organization
# Date: 2023-10-27
# Version: 1.0.0
# win_activity_viewer_pro.py
import sys
import os
import sqlite3
import shutil
import tempfile
from datetime import datetime

import qtawesome as qta
from PyQt5.QtCore import Qt, QPropertyAnimation, QEasingCurve, QTimer, QByteArray
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit,
    QFileDialog, QMessageBox, QLabel, QSizePolicy, QFrame
)
import win32evtlog

# --------------------------
# Utility / Data functions
# --------------------------
def safe_copy_db(src_path):
    """Copy DB to temp location (works even if file 'locked' by browser)."""
    try:
        if not os.path.exists(src_path):
            return None
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=os.path.basename(src_path))
        os.close(tmp_fd)
        shutil.copy2(src_path, tmp_path)
        return tmp_path
    except Exception:
        return None

def query_sqlite_file(db_path, query, params=()):
    tmp = safe_copy_db(db_path)
    if not tmp:
        return []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        conn.close()
    except Exception:
        rows = []
    try:
        os.remove(tmp)
    except Exception:
        pass
    return rows

def get_recent_files(limit=30):
    recent_folder = os.path.expanduser(r"~\AppData\Roaming\Microsoft\Windows\Recent")
    if not os.path.exists(recent_folder):
        return []
    try:
        entries = sorted(os.listdir(recent_folder), reverse=True)
        files = [e for e in entries if os.path.isfile(os.path.join(recent_folder, e))]
        return files[:limit]
    except Exception:
        return []

def get_event_logs(log_type="System", event_ids=None, max_events=50):
    server = "localhost"
    try:
        handle = win32evtlog.OpenEventLog(server, log_type)
    except Exception as e:
        return [f"Fehler: {e}"]
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    results = []
    count = 0
    try:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        for ev in events:
            try:
                ev_id = int(ev.EventID) & 0xFFFF
            except Exception:
                ev_id = getattr(ev, "EventID", "unknown")
            if event_ids is None or ev_id in event_ids:
                ts = getattr(ev, "TimeGenerated", None)
                ts_str = ts.Format() if hasattr(ts, "Format") else str(ts)
                results.append(f"{ts_str}  |  EventID: {ev_id}  |  Source: {getattr(ev, 'SourceName', '')}")
                count += 1
                if count >= max_events:
                    break
    except Exception as e:
        results.append(f"Fehler beim Lesen des EventLogs: {e}")
    return results

def get_chrome_history(limit=10):
    path = os.path.expanduser(r"~\AppData\Local\Google\Chrome\User Data\Default\History")
    if not os.path.exists(path):
        return []
    q = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?;"
    rows = query_sqlite_file(path, q, (limit,))
    out = []
    for r in rows:
        url = r[0] if len(r) > 0 else ""
        title = r[1] if len(r) > 1 else ""
        out.append(f"{title or '—'}  —  {url}")
    return out

def get_edge_history(limit=10):
    path = os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\User Data\Default\History")
    if not os.path.exists(path):
        return []
    q = "SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?;"
    rows = query_sqlite_file(path, q, (limit,))
    out = []
    for r in rows:
        url = r[0] if len(r) > 0 else ""
        title = r[1] if len(r) > 1 else ""
        out.append(f"{title or '—'}  —  {url}")
    return out

def get_firefox_history(limit=10):
    profiles = os.path.expanduser(r"~\AppData\Roaming\Mozilla\Firefox\Profiles")
    if not os.path.exists(profiles):
        return []
    try:
        profs = [p for p in os.listdir(profiles) if os.path.isdir(os.path.join(profiles, p))]
        if not profs:
            return []
        profile = profs[0]
        path = os.path.join(profiles, profile, "places.sqlite")
        q = "SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT ?;"
        rows = query_sqlite_file(path, q, (limit,))
        out = []
        for r in rows:
            url = r[0] if len(r) > 0 else ""
            title = r[1] if len(r) > 1 else ""
            out.append(f"{title or '—'}  —  {url}")
        return out
    except Exception:
        return []

# --------------------------
# UI: Animated, polished
# --------------------------
class AnimatedButton(QPushButton):
    def __init__(self, icon, label, parent=None):
        super().__init__(label, parent)
        self.setIcon(icon)
        self.setIconSize(Qt.QSize(20, 20))
        self.setCursor(Qt.PointingHandCursor)
        # style is controlled by parent stylesheet

class ActivityViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WinActivityViewer Pro")
        self.setGeometry(120, 80, 1200, 760)
        self.setFont(QFont("Segoe UI", 10))
        self.setup_ui()
        QTimer.singleShot(150, self.play_open_animation)

    def setup_ui(self):
        # main layout
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        # sidebar frame (animated width)
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(260)
        sb_layout = QVBoxLayout(self.sidebar)
        sb_layout.setContentsMargins(16, 20, 16, 16)
        sb_layout.setSpacing(12)

        # Title
        title = QLabel("WinActivityViewer ✨")
        title.setObjectName("appTitle")
        title.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        sb_layout.addWidget(title)

        # Buttons with qtawesome icons
        self.btn_files = AnimatedButton(qta.icon('fa.folder'), " Dateien", self)
        self.btn_logons = AnimatedButton(qta.icon('fa.sign-in'), " Logins", self)
        self.btn_start = AnimatedButton(qta.icon('fa.power-off'), " Start/Shutdown", self)
        self.btn_browser = AnimatedButton(qta.icon('fa.chrome'), " Browser", self)
        self.btn_summary = AnimatedButton(qta.icon('fa.chart-bar'), " Zusammenfassung", self)
        self.btn_export = AnimatedButton(qta.icon('fa.save'), " Exportieren", self)

        for b in (self.btn_files, self.btn_logons, self.btn_start, self.btn_browser, self.btn_summary):
            b.setFixedHeight(46)
            sb_layout.addWidget(b)

        sb_layout.addStretch()
        self.btn_export.setFixedHeight(44)
        sb_layout.addWidget(self.btn_export)

        # content frame
        self.content = QFrame()
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(20, 20, 20, 20)
        content_layout.setSpacing(12)

        header = QLabel("Ergebnisse")
        header.setObjectName("header")
        content_layout.addWidget(header)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("padding:12px; border-radius:8px;")
        content_layout.addWidget(self.output)

        # add to root
        root.addWidget(self.sidebar)
        root.addWidget(self.content, 1)

        # connect buttons
        self.btn_files.clicked.connect(self.on_files)
        self.btn_logons.clicked.connect(self.on_logons)
        self.btn_start.clicked.connect(self.on_start)
        self.btn_browser.clicked.connect(self.on_browser)
        self.btn_summary.clicked.connect(self.on_summary)
        self.btn_export.clicked.connect(self.on_export)

        # stylesheet (dark, hover, subtle shadows)
        self.setStyleSheet("""
            QWidget { background: #0f1113; color: #e6eef8; }
            #sidebar { background: qlineargradient(spread:pad, x1:0, y1:0, x2:1, y2:0, stop:0 #131417, stop:1 #18191b); }
            #appTitle { font-size: 18px; font-weight: 700; margin-bottom: 6px; }
            #header { font-size: 16px; font-weight: 600; margin-bottom: 8px; color: #cfe8ff; }
            QPushButton { background: transparent; color: #dfe9f3; border: none; text-align: left; padding-left:6px; font-size:13px; }
            QPushButton:hover { background: rgba(255,255,255,0.03); border-radius:6px; }
            QPushButton:pressed { background: rgba(255,255,255,0.05); }
            QTextEdit { background: #0b0c0d; border: 1px solid #1e2933; color: #d0e7ff; font-family: Consolas, monospace; font-size: 12px; }
        """)

    # -------------------
    # Animations
    # -------------------
    def play_open_animation(self):
        # slide in sidebar from left (width animation)
        anim = QPropertyAnimation(self.sidebar, b"minimumWidth")
        anim.setStartValue(0)
        anim.setEndValue(260)
        anim.setDuration(420)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start()
        # keep reference to avoid garbage collection
        self._open_anim = anim

    def fade_in_output(self, text, duration=350):
        # quick fade-out then fade-in (simulate)
        self.output.setPlainText("")  # clear first
        # use a QTimer to step-in lines for 'typewriter' effect
        lines = text.splitlines()
        if not lines:
            self.output.setPlainText("")
            return
        self._line_index = 0
        self._lines = lines
        self._type_timer = QTimer(self)
        self._type_timer.setInterval(int(max(8, duration / max(1, len(lines)))))  # ms per line
        self._type_timer.timeout.connect(self._append_line)
        self._type_timer.start()

    def _append_line(self):
        if self._line_index >= len(self._lines):
            self._type_timer.stop()
            return
        self.output.append(self._lines[self._line_index])
        self._line_index += 1

    # -------------------
    # Button handlers (gather + display)
    # -------------------
    def on_files(self):
        files = get_recent_files(80)
        text = "📂 Zuletzt geöffnete Dateien:\n\n"
        if not files:
            text += "Keine Einträge gefunden."
        else:
            for f in files:
                text += f" - {f}\n"
        self.fade_in_output(text)

    def on_logons(self):
        logs = get_event_logs("Security", event_ids=[4624, 4634], max_events=80)
        text = "🔐 An-/Abmeldungen:\n\n" + ("\n".join(logs) if logs else "Keine Einträge.")
        self.fade_in_output(text)

    def on_start(self):
        logs = get_event_logs("System", event_ids=[6005, 6006], max_events=80)
        text = "💻 Start / Herunterfahren:\n\n" + ("\n".join(logs) if logs else "Keine Einträge.")
        self.fade_in_output(text)

    def on_browser(self):
        chrome = get_chrome_history(12)
        edge = get_edge_history(12)
        firefox = get_firefox_history(12)
        text = "🌐 Browser-Verlauf\n\n--- Chrome ---\n"
        text += ("\n".join(chrome) if chrome else "Keine Einträge.") + "\n\n"
        text += "--- Edge ---\n" + ("\n".join(edge) if edge else "Keine Einträge.") + "\n\n"
        text += "--- Firefox ---\n" + ("\n".join(firefox) if firefox else "Keine Einträge.")
        self.fade_in_output(text)

    def on_summary(self):
        files = get_recent_files(8)
        logins = get_event_logs("Security", event_ids=[4624], max_events=6)
        starts = get_event_logs("System", event_ids=[6005], max_events=6)
        chrome = get_chrome_history(6)
        dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        text = f"=== Zusammenfassung ({dt}) ===\n\n"
        text += "📂 Dateien (letzte):\n" + ("\n".join(files) if files else "Keine Einträge.") + "\n\n"
        text += "🔐 Letzte Logins:\n" + ("\n".join(logins) if logins else "Keine Einträge.") + "\n\n"
        text += "💻 Letzte Systemstarts:\n" + ("\n".join(starts) if starts else "Keine Einträge.") + "\n\n"
        text += "🌐 Browser (Chrome, letzte 6):\n" + ("\n".join(chrome) if chrome else "Keine Einträge.")
        self.fade_in_output(text)

    def on_export(self):
        # Build full summary (like on_summary but more)
        files = get_recent_files(50)
        logins = get_event_logs("Security", event_ids=[4624, 4634], max_events=200)
        starts = get_event_logs("System", event_ids=[6005, 6006], max_events=200)
        chrome = get_chrome_history(50)
        edge = get_edge_history(50)
        firefox = get_firefox_history(50)
        dt = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body = f"=== Export: WinActivityViewer Pro ({dt}) ===\n\n"
        body += "=== Dateien (Recent) ===\n" + ("\n".join(files) if files else "Keine Einträge.") + "\n\n"
        body += "=== Logins/Logouts ===\n" + ("\n".join(logins) if logins else "Keine Einträge.") + "\n\n"
        body += "=== Start / Shutdown ===\n" + ("\n".join(starts) if starts else "Keine Einträge.") + "\n\n"
        body += "=== Chrome (Top) ===\n" + ("\n".join(chrome) if chrome else "Keine Einträge.") + "\n\n"
        body += "=== Edge (Top) ===\n" + ("\n".join(edge) if edge else "Keine Einträge.") + "\n\n"
        body += "=== Firefox (Top) ===\n" + ("\n".join(firefox) if firefox else "Keine Einträge.") + "\n"
        fname, _ = QFileDialog.getSaveFileName(self, "Export speichern", f"WinActivityExport_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", "Textdateien (*.txt)")
        if fname:
            try:
                with open(fname, "w", encoding="utf-8") as fh:
                    fh.write(body)
                QMessageBox.information(self, "Export", f"Export gespeichert:\n{fname}")
            except Exception as e:
                QMessageBox.critical(self, "Fehler", f"Konnte nicht speichern: {e}")

 

# --------------------------
# App start
# --------------------------
def main():
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_UseHighDpiPixmaps)
    viewer = ActivityViewer()
    viewer.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
