#!/usr/bin/env python3
"""
antivirus_file_scanner_gui.py
----------------------------------------
Attractive GUI Antivirus File Scanner
(For LA2 Advanced Operating System Project)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

# --- Simple Signature Database (simulation) ---
VIRUS_SIGNATURES = [
    "malware", "virus", "trojan", "worm", "spyware",
    "ransomware", "keylogger", "hacktool", "backdoor"
]

# --- Function to Scan a File for Virus Keywords ---
def scan_file(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read().lower()
            for signature in VIRUS_SIGNATURES:
                if signature.encode() in content:
                    return f"⚠️ Infected! Detected signature: '{signature}'"
        return "✅ Safe! No virus signature found."
    except Exception as e:
        return f"❌ Error scanning file: {e}"

# --- Choose and Scan File Function ---
def choose_file():
    file_path = filedialog.askopenfilename(title="Select File to Scan")
    if not file_path:
        return
    try:
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)
        result_text.set(f"📂 File: {file_name}\n💾 Size: {file_size} bytes\n\n🔍 Scanning...")
        root.update_idletasks()

        # Perform the scan
        scan_result = scan_file(file_path)

        # Show result
        result_text.set(f"📂 File: {file_name}\n💾 Size: {file_size} bytes\n\n{scan_result}")

    except Exception as e:
        messagebox.showerror("Error", f"Failed to process file:\n{e}")

# --- Clear Output ---
def clear_output():
    result_text.set("")

# --- MAIN WINDOW ---
root = tk.Tk()
root.title("🛡️ Simple Antivirus Scanner")
root.geometry("600x400")
root.configure(bg="#eaf4fc")
root.resizable(False, False)

# --- Styling ---
style = ttk.Style()
style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=6)
style.configure("Header.TLabel", font=("Segoe UI", 15, "bold"), background="#eaf4fc", foreground="#003366")

# --- Header ---
header = ttk.Label(root, text="🛡️ Antivirus File Scanner", style="Header.TLabel")
header.pack(pady=(20, 10))

# --- Button Frame ---
frame = ttk.Frame(root, padding=10)
frame.pack()

upload_btn = ttk.Button(frame, text="Select File & Scan", command=choose_file)
upload_btn.grid(row=0, column=0, padx=10, pady=5)

clear_btn = ttk.Button(frame, text="Clear", command=clear_output)
clear_btn.grid(row=0, column=1, padx=10, pady=5)

# --- Output Area ---
result_text = tk.StringVar()
result_label = ttk.Label(root, textvariable=result_text, wraplength=500, justify="left",
                         background="#f7fbff", relief="groove", padding=10, anchor="w")
result_label.pack(fill="x", padx=20, pady=20)

# --- Footer ---
footer = ttk.Label(root, text="© 2025 Advanced OS Project | Developed by [Your Name]",
                   font=("Segoe UI", 9, "italic"), background="#eaf4fc")
footer.pack(side="bottom", pady=10)

# --- Run App ---
root.mainloop()
