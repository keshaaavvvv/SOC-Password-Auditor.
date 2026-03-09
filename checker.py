import customtkinter as ctk
import re
import math
import secrets
import string
import pyperclip

# System Settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class SOCSentinel(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("SOC Sentinel - Security Auditor")
        self.geometry("550x700")

        # --- Header ---
        self.title_label = ctk.CTkLabel(self, text="SOC PASSWORD AUDITOR", font=("Consolas", 24, "bold"), text_color="#38bdf8")
        self.title_label.pack(pady=20)

        # --- Input Frame ---
        self.input_frame = ctk.CTkFrame(self)
        self.input_frame.pack(pady=10, padx=30, fill="x")

        self.pwd_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter password for analysis...", show="*", height=45, font=("Arial", 14))
        self.pwd_entry.pack(pady=15, padx=20, fill="x")
        self.pwd_entry.bind("<KeyRelease>", self.run_audit)

        # --- Visual Meters ---
        self.strength_bar = ctk.CTkProgressBar(self, width=400, height=12)
        self.strength_bar.set(0)
        self.strength_bar.pack(pady=10)

        self.status_label = ctk.CTkLabel(self, text="Security Level: Pending Scan", font=("Arial", 13, "italic"))
        self.status_label.pack()

        # --- Metrics Grid ---
        self.metrics_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.metrics_frame.pack(pady=15)

        self.entropy_label = ctk.CTkLabel(self.metrics_frame, text="Entropy: 0 bits", font=("Consolas", 12))
        self.entropy_label.grid(row=0, column=0, padx=20)

        self.crack_label = ctk.CTkLabel(self.metrics_frame, text="Crack Time: Instant", font=("Consolas", 12))
        self.crack_label.grid(row=0, column=1, padx=20)

        # --- Results / Logs ---
        self.log_view = ctk.CTkTextbox(self, width=450, height=200, font=("Consolas", 12), fg_color="#020617", text_color="#10b981")
        self.log_view.pack(pady=10)

        # --- Buttons ---
        self.gen_button = ctk.CTkButton(self, text="Generate Secure Passphrase", command=self.generate_secure, font=("Arial", 13, "bold"), fg_color="#1e40af", hover_color="#1e3a8a")
        self.gen_button.pack(pady=5)

        self.copy_button = ctk.CTkButton(self, text="Copy to Clipboard", command=self.copy_action, fg_color="#334155")
        self.copy_button.pack(pady=5)

    def calculate_metrics(self, pwd):
        if not pwd: return 0, 0, "N/A"
        
        charset = 0
        if re.search(r'[a-z]', pwd): charset += 26
        if re.search(r'[A-Z]', pwd): charset += 26
        if re.search(r'[0-9]', pwd): charset += 10
        if re.search(r'[^a-zA-Z0-9]', pwd): charset += 32
        
        entropy = len(pwd) * math.log2(charset) if charset > 0 else 0
        
        # Estimate crack time (Assuming 10 billion guesses/sec - typical GPU cluster)
        combinations = charset ** len(pwd)
        seconds = combinations / 1e10
        
        if seconds < 60: crack_time = f"{round(seconds, 2)} secs"
        elif seconds < 3600: crack_time = f"{round(seconds/60, 1)} mins"
        elif seconds < 86400: crack_time = f"{round(seconds/3600, 1)} hours"
        elif seconds < 31536000: crack_time = f"{round(seconds/86400, 1)} days"
        else: crack_time = f"{round(seconds/31536000, 1)} years"
            
        return entropy, combinations, crack_time

    def run_audit(self, event=None):
        pwd = self.pwd_entry.get()
        entropy, comps, crack_time = self.calculate_metrics(pwd)
        
        # Scoring Logic
        score = 0
        logs = [">>> INITIATING THREAT ANALYSIS..."]
        
        if len(pwd) >= 12: score += 0.4
        else: logs.append("[!] RISK: Short length increases brute-force vulnerability.")
            
        if re.search(r'[A-Z]', pwd) and re.search(r'[a-z]', pwd): score += 0.2
        else: logs.append("[!] RISK: Missing casing diversity.")
            
        if re.search(r'[0-9]', pwd): score += 0.2
        if re.search(r'[^a-zA-Z0-9]', pwd): score += 0.2

        # Update UI
        self.strength_bar.set(score)
        self.entropy_label.configure(text=f"Entropy: {round(entropy, 1)} bits")
        self.crack_label.configure(text=f"Crack Time: {crack_time}")
        
        if score < 0.4: color = "#ef4444"; status = "CRITICAL"
        elif score < 0.8: color = "#f59e0b"; status = "VULNERABLE"
        else: color = "#22c55e"; status = "SECURE"
            
        self.status_label.configure(text=f"Security Level: {status}", text_color=color)
        self.strength_bar.configure(progress_color=color)
        
        self.log_view.delete("1.0", "end")
        self.log_view.insert("end", "\n".join(logs))

    def generate_secure(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
        self.pwd_entry.delete(0, "end")
        self.pwd_entry.insert(0, pwd)
        self.run_audit()

    def copy_action(self):
        pyperclip.copy(self.pwd_entry.get())

if __name__ == "__main__":
    app = SOCSentinel()
    app.mainloop()