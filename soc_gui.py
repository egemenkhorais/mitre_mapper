"""
MITRE Mapper Desktop GUI (live)
Author: Egemen Koray Keleş (github.com/egemenkhorais)

live_soc.py'nin alerts/ klasörüne yazdığı gerçek metadata dosyalarını
izler; mock/seed veri yoktur. Web sunucusuna ihtiyaç duymaz.

Kullanım:
    python soc_gui.py
    python soc_gui.py --alerts-dir /yol/alerts
"""

import argparse
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from soc_store import AlertStore, DEFAULT_ALERTS_DIR, DEFAULT_ATTACK_JSON

POLL_MS = 1000

SEV_TR = {
    "critical": "Kritik",
    "high": "Yüksek",
    "medium": "Orta",
    "low": "Düşük",
    "informational": "Bilgi",
}


class MitreMapperApp(tk.Tk):
    def __init__(self, alerts_dir, attack_json):
        super().__init__()
        self.title("MITRE Mapper - Live SOC")
        self.geometry("1200x740")
        self.minsize(1000, 620)
        self.configure(bg="#0b0f19")

        self.store = AlertStore(alerts_dir, attack_json)
        self.last_seq = 0
        self.row_to_alert = {}

        self._setup_styles()
        self._build_ui()
        self._poll()

    # ---------------------------------------------------------
    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background="#0b0f19", foreground="#e2e8f0", font=("Inter", 9))
        style.configure("TNotebook", background="#0f172a", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1e293b", foreground="#94a3b8",
                        padding=[16, 8], font=("Inter", 9, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#0284c7")],
                  foreground=[("selected", "#ffffff")])
        style.configure("Treeview", background="#0f172a", fieldbackground="#0f172a",
                        foreground="#f8fafc", rowheight=26, font=("JetBrains Mono", 9))
        style.configure("Treeview.Heading", background="#1e293b", foreground="#38bdf8",
                        font=("Inter", 9, "bold"))
        style.map("Treeview", background=[("selected", "#0369a1")])

    def _build_ui(self):
        header = tk.Frame(self, bg="#0f172a", height=50)
        header.pack(fill=tk.X, side=tk.TOP)

        tk.Label(header, text="MITRE Mapper", font=("Inter", 13, "bold"),
                 fg="#38bdf8", bg="#0f172a").pack(side=tk.LEFT, padx=16, pady=10)
        tk.Label(header, text="github.com/egemenkhorais/mitre_mapper",
                 font=("JetBrains Mono", 9), fg="#64748b", bg="#0f172a").pack(side=tk.LEFT, padx=4)

        tk.Button(header, text="Export ATT&CK Navigator JSON", font=("Inter", 9),
                  bg="#0284c7", fg="#ffffff", activebackground="#0369a1", relief=tk.FLAT,
                  padx=10, pady=4, command=self.export_navigator_json).pack(side=tk.RIGHT, padx=16)

        self.lbl_status = tk.Label(header, text="", font=("JetBrains Mono", 9),
                                   fg="#94a3b8", bg="#0f172a")
        self.lbl_status.pack(side=tk.RIGHT, padx=8)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        self.tab_live = tk.Frame(self.notebook, bg="#0b0f19")
        self.tab_matrix = tk.Frame(self.notebook, bg="#0b0f19")
        self.tab_rules = tk.Frame(self.notebook, bg="#0b0f19")

        self.notebook.add(self.tab_live, text="  Canlı Alert & Triage  ")
        self.notebook.add(self.tab_matrix, text="  ATT&CK Matrisi  ")
        self.notebook.add(self.tab_rules, text="  Gözlenen Eşlemeler  ")

        self._build_live_tab()
        self._build_matrix_tab()
        self._build_rules_tab()

    # ---------------------------------------------------------
    def _build_live_tab(self):
        # Üst: KPI şeridi
        kpi = tk.Frame(self.tab_live, bg="#0b0f19")
        kpi.pack(fill=tk.X, pady=(4, 8))
        self.kpi_labels = {}
        for key, title in (("total", "İşlenen Alert"), ("techniques", "MITRE Tekniği"),
                           ("critical", "Kritik/Yüksek"), ("conf", "Ort. Güven")):
            box = tk.Frame(kpi, bg="#0f172a", padx=14, pady=8)
            box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
            tk.Label(box, text=title, fg="#94a3b8", bg="#0f172a",
                     font=("JetBrains Mono", 8)).pack(anchor=tk.W)
            lbl = tk.Label(box, text="-", fg="#38bdf8", bg="#0f172a",
                           font=("JetBrains Mono", 14, "bold"))
            lbl.pack(anchor=tk.W)
            self.kpi_labels[key] = lbl

        # Seçili alert özeti
        res_box = tk.LabelFrame(self.tab_live, text=" Seçili Alert / MITRE Triage ", fg="#38bdf8",
                                bg="#0f172a", font=("Inter", 9, "bold"), padx=12, pady=10)
        res_box.pack(fill=tk.X, pady=(0, 8))

        self.lbl_attack = tk.Label(res_box, text="Alert bekleniyor…", font=("Inter", 11, "bold"),
                                   fg="#f43f5e", bg="#0f172a")
        self.lbl_attack.pack(anchor=tk.W)
        self.lbl_flow = tk.Label(res_box, text="", font=("JetBrains Mono", 9),
                                 fg="#94a3b8", bg="#0f172a")
        self.lbl_flow.pack(anchor=tk.W)
        self.lbl_mitre = tk.Label(res_box, text="", font=("JetBrains Mono", 10),
                                  fg="#38bdf8", bg="#0f172a", wraplength=1050, justify=tk.LEFT)
        self.lbl_mitre.pack(anchor=tk.W, pady=3)
        self.lbl_conf = tk.Label(res_box, text="", font=("Inter", 9), fg="#a855f7", bg="#0f172a")
        self.lbl_conf.pack(anchor=tk.W)
        self.lbl_detail = tk.Label(res_box, text="", font=("Inter", 9), fg="#cbd5e1", bg="#0f172a",
                                   wraplength=1050, justify=tk.LEFT)
        self.lbl_detail.pack(anchor=tk.W, pady=4)

        # Alert tablosu
        hist = tk.LabelFrame(self.tab_live, text=" Son Alert'ler ", fg="#94a3b8", bg="#0f172a",
                             font=("Inter", 9, "bold"), padx=6, pady=6)
        hist.pack(fill=tk.BOTH, expand=True)

        cols = ("Time", "Decision", "Label", "Flow", "Tactic", "Tech_ID", "Tech_Name", "Conf", "Severity")
        self.tree_alerts = ttk.Treeview(hist, columns=cols, show="headings", height=10)
        widths = {"Time": 70, "Decision": 110, "Label": 150, "Flow": 260, "Tactic": 130,
                  "Tech_ID": 80, "Tech_Name": 190, "Conf": 60, "Severity": 70}
        for col in cols:
            self.tree_alerts.heading(col, text=col)
            self.tree_alerts.column(col, width=widths[col])

        scroll = ttk.Scrollbar(hist, orient=tk.VERTICAL, command=self.tree_alerts.yview)
        self.tree_alerts.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_alerts.pack(fill=tk.BOTH, expand=True)
        self.tree_alerts.bind("<<TreeviewSelect>>", self._on_select)

    def _build_matrix_tab(self):
        container = tk.Frame(self.tab_matrix, bg="#0f172a", padx=16, pady=16)
        container.pack(fill=tk.BOTH, expand=True)
        tk.Label(container, text="MITRE ATT&CK - gözlenen teknikler (gerçek alert'lerden)",
                 font=("Inter", 11, "bold"), fg="#38bdf8", bg="#0f172a").pack(anchor=tk.W, pady=(0, 10))

        # Yatay kaydırılabilir alan
        canvas = tk.Canvas(container, bg="#0f172a", highlightthickness=0)
        hbar = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=canvas.xview)
        canvas.configure(xscrollcommand=hbar.set)
        hbar.pack(side=tk.BOTTOM, fill=tk.X)
        canvas.pack(fill=tk.BOTH, expand=True)

        self.matrix_frame = tk.Frame(canvas, bg="#0f172a")
        canvas.create_window((0, 0), window=self.matrix_frame, anchor="nw")
        self.matrix_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

    def _build_rules_tab(self):
        container = tk.Frame(self.tab_rules, bg="#0f172a", padx=16, pady=16)
        container.pack(fill=tk.BOTH, expand=True)
        tk.Label(container, text="Model etiketi -> MITRE tekniği (gözlenen eşlemeler)",
                 font=("Inter", 11, "bold"), fg="#38bdf8", bg="#0f172a").pack(anchor=tk.W, pady=(0, 10))

        cols = ("Attack", "Tactic", "Tech_ID", "Tech_Name", "Count", "AvgConf", "MaxSeverity")
        self.tree_rules = ttk.Treeview(container, columns=cols, show="headings")
        for col in cols:
            self.tree_rules.heading(col, text=col)
            self.tree_rules.column(col, width=120)
        self.tree_rules.column("Tech_Name", width=240)
        self.tree_rules.pack(fill=tk.BOTH, expand=True)

    # ---------------------------------------------------------
    def _poll(self):
        try:
            self.store.refresh()
            fresh = self.store.alerts_since(self.last_seq)

            for alert in fresh:
                self._insert_alert(alert)
                self.last_seq = max(self.last_seq, alert["seq"])

            if fresh:
                self._refresh_aggregates()
                self._show_alert(fresh[-1])

            exists = self.store.alerts_dir.exists()
            self.lbl_status.config(
                text=("● canlı · " if exists else "● klasör yok · ") + str(self.store.alerts_dir),
                fg="#34d399" if exists else "#f43f5e",
            )
        except Exception as exc:
            self.lbl_status.config(text=f"● hata: {exc!r}", fg="#f43f5e")

        self.after(POLL_MS, self._poll)

    def _insert_alert(self, a):
        p = a["primary"] or {}
        iid = self.tree_alerts.insert(
            "", 0,
            iid=f"{a['id']}#{a['seq']}",
            values=(
                a["time"], a["decision"], a["label"],
                f"{a['src_ip']}:{a['src_port']} -> {a['dst_ip']}:{a['dst_port']}",
                p.get("tactic", "-"), p.get("id", a["mitre_status"]), p.get("name", ""),
                f"{a['confidence'] * 100:.1f}%", SEV_TR.get(a["severity"], a["severity"]),
            ),
        )
        self.row_to_alert[iid] = a

        # Tabloyu sınırla
        children = self.tree_alerts.get_children()
        for old in children[500:]:
            self.tree_alerts.delete(old)
            self.row_to_alert.pop(old, None)

    def _on_select(self, _event):
        sel = self.tree_alerts.selection()
        if sel and sel[0] in self.row_to_alert:
            self._show_alert(self.row_to_alert[sel[0]])

    def _show_alert(self, a):
        self.lbl_attack.config(text=f"Alert: {a['label']}  [{a['decision']}]")
        self.lbl_flow.config(
            text=f"{a['src_ip']}:{a['src_port']} -> {a['dst_ip']}:{a['dst_port']}  "
                 f"proto={a['protocol']}  pkts={a['packet_count']}"
        )

        if a["techniques"]:
            self.lbl_mitre.config(
                text="MITRE: " + " | ".join(
                    f"{t['id']} {t['name']} ({t['confidence'] * 100:.0f}%)" for t in a["techniques"]
                )
            )
        else:
            why = a["mitre_message"] or a["mitre_reason"] or ""
            self.lbl_mitre.config(text=f"MITRE: teknik yok (status={a['mitre_status']}) {why}")

        self.lbl_conf.config(
            text=f"Layer-1 güven: {a['confidence'] * 100:.1f}%   Risk: {a['risk_score']:g} "
                 f"({SEV_TR.get(a['severity'], a['severity'])})"
        )

        parts = []
        l2 = a["layer2"]
        if l2:
            parts.append(f"Layer-2: {l2.get('label')} ({l2.get('status')})")
        if a["behaviors"]:
            parts.append("Davranış: " + ", ".join(b for b in a["behaviors"] if b))
        act = a["source_activity"] or {}
        if act:
            parts.append(f"Kaynak aktivite: {act.get('flow_count', 0)} flow, "
                         f"{act.get('unique_dst_ports', 0)} port, {act.get('unique_dst_ips', 0)} host")
        if a["retained_reason"]:
            parts.append(f"Korunma nedeni: {a['retained_reason']}")
        self.lbl_detail.config(text="  |  ".join(parts))

    # ---------------------------------------------------------
    def _refresh_aggregates(self):
        s = self.store.stats()
        self.kpi_labels["total"].config(text=str(s["total_alerts"]))
        self.kpi_labels["techniques"].config(text=str(s["mapped_techniques"]))
        self.kpi_labels["critical"].config(text=str(s["critical_high"]))
        self.kpi_labels["conf"].config(
            text="-" if s["avg_confidence"] is None else f"{s['avg_confidence'] * 100:.1f}%"
        )

        # Matris
        for child in self.matrix_frame.winfo_children():
            child.destroy()

        colors = {"crit": "#9f1239", "high": "#b45309", "med": "#0369a1"}
        for i, tactic in enumerate(self.store.matrix()["tactics"]):
            col = tk.Frame(self.matrix_frame, bg="#1e293b", padx=8, pady=8,
                           highlightbackground="#334155", highlightthickness=1)
            col.grid(row=0, column=i, sticky="nsew", padx=4, pady=4)
            tk.Label(col, text=tactic["name"], font=("Inter", 9, "bold"),
                     fg="#38bdf8", bg="#1e293b", wraplength=140).pack(anchor=tk.W, pady=(0, 6))

            if not tactic["techniques"]:
                tk.Label(col, text="eşleşme yok", font=("JetBrains Mono", 8),
                         fg="#475569", bg="#1e293b").pack(anchor=tk.W)

            for t in tactic["techniques"]:
                tk.Label(col, text=f"{t['id']}  x{t['count']}\n{t['name']}",
                         font=("JetBrains Mono", 8), fg="#f8fafc", bg=colors[t["level"]],
                         padx=6, pady=4, wraplength=130, justify=tk.LEFT).pack(fill=tk.X, pady=2)

        # Eşlemeler
        for row in self.tree_rules.get_children():
            self.tree_rules.delete(row)
        for m in self.store.mappings():
            self.tree_rules.insert("", tk.END, values=(
                m["attack"], m["tactic"], m["tech_id"], m["tech_name"], m["count"],
                f"{m['avg_confidence'] * 100:.1f}%", SEV_TR.get(m["max_severity"], m["max_severity"]),
            ))

    def export_navigator_json(self):
        techniques = {}
        for m in self.store.mappings():
            tid = m["tech_id"].split(".")[0]
            e = techniques.setdefault(tid, {"techniqueID": tid, "score": 0, "comment": "", "enabled": True})
            e["score"] += m["count"]
            e["comment"] += f"{m['attack']} x{m['count']}; "

        if not techniques:
            messagebox.showinfo("Bilgi", "Henüz MITRE eşlemesi yok; dışa aktarılacak teknik bulunamadı.")
            return

        layer = {
            "name": "MITRE Mapper - live alerts",
            "versions": {"attack": "14", "navigator": "4.8.1", "layer": "4.4"},
            "domain": "enterprise-attack",
            "techniques": list(techniques.values()),
        }

        filename = filedialog.asksaveasfilename(defaultextension=".json",
                                                filetypes=[("JSON files", "*.json")])
        if filename:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(layer, f, indent=2)
            messagebox.showinfo("Başarılı", f"Navigator katmanı kaydedildi:\n{filename}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--alerts-dir", default=str(DEFAULT_ALERTS_DIR))
    parser.add_argument("--attack-json", default=str(DEFAULT_ATTACK_JSON))
    args = parser.parse_args()

    MitreMapperApp(args.alerts_dir, args.attack_json).mainloop()