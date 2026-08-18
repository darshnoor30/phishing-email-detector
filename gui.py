"""Small desktop interface for the phishing email detector."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from phishing_detector import analyze_email


class DetectorApp(ttk.Frame):
    def __init__(self, master: tk.Tk) -> None:
        super().__init__(master, padding=20)
        self.grid(sticky="nsew")
        master.title("Phishing Email Detector")
        master.geometry("760x620")
        master.minsize(620, 480)
        master.columnconfigure(0, weight=1)
        master.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        self.rowconfigure(5, weight=1)

        ttk.Label(
            self,
            text="Explainable Phishing Email Detector",
            font=("TkDefaultFont", 17, "bold"),
        ).grid(row=0, column=0, sticky="w")
        ttk.Label(
            self,
            text="Paste a message below. Analysis stays on this device.",
        ).grid(row=1, column=0, sticky="w", pady=(4, 8))

        self.message = tk.Text(self, wrap="word", height=12, undo=True)
        self.message.grid(row=2, column=0, sticky="nsew")
        self.message.focus_set()

        controls = ttk.Frame(self)
        controls.grid(row=3, column=0, sticky="ew", pady=10)
        ttk.Button(controls, text="Analyze email", command=self.analyze).pack(
            side="left"
        )
        ttk.Button(controls, text="Clear", command=self.clear).pack(side="left", padx=8)

        self.risk_label = ttk.Label(
            self, text="No message analyzed", font=("TkDefaultFont", 12, "bold")
        )
        self.risk_label.grid(row=4, column=0, sticky="w", pady=(2, 6))

        self.result = tk.Text(self, wrap="word", state="disabled", height=12)
        self.result.grid(row=5, column=0, sticky="nsew")

        ttk.Label(
            self,
            text=(
                "Rule-based triage supports review; it does not prove a message "
                "is safe."
            ),
        ).grid(row=6, column=0, sticky="w", pady=(8, 0))

    def analyze(self) -> None:
        message = self.message.get("1.0", "end-1c")
        if not message.strip():
            messagebox.showwarning("Missing email", "Paste an email message first.")
            return

        analysis = analyze_email(message)
        self.risk_label.configure(
            text=f"{analysis.severity} risk · {analysis.score}/100 — {analysis.summary}"
        )
        details: list[str] = []
        if analysis.indicators:
            details.append("Indicators")
            details.extend(
                f"• {item.title} (+{item.weight})\n  {item.evidence}"
                for item in analysis.indicators
            )
        else:
            details.append("No rule-based indicators were detected.")
        details.append("\nRecommended next steps")
        details.extend(f"• {item}" for item in analysis.recommendations)

        self.result.configure(state="normal")
        self.result.delete("1.0", "end")
        self.result.insert("1.0", "\n".join(details))
        self.result.configure(state="disabled")

    def clear(self) -> None:
        self.message.delete("1.0", "end")
        self.result.configure(state="normal")
        self.result.delete("1.0", "end")
        self.result.configure(state="disabled")
        self.risk_label.configure(text="No message analyzed")
        self.message.focus_set()


def main() -> None:
    root = tk.Tk()
    DetectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
