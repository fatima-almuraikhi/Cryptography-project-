# client_final.py
import threading, json
from tkinter import Tk, Label, Entry, Button, scrolledtext, messagebox, simpledialog
# In a real structure, we would import logic from Phase 2
from client_phase1 import CoreClient
from client_phase2 import LogicClient

class FullClientLogic(CoreClient, LogicClient):
    pass # Inherits all capabilities from Phase 1 and 2

class ClientGUI(Tk):
    # GUI IMPLEMENTATION ---
    def __init__(self):
        super().__init__()
        self.title("Phase 3: Final Team Submission")
        self.geometry("500x500")
        self.client = FullClientLogic()

        # UI Layout
        Label(self, text="Username:").pack()
        self.user_entry = Entry(self); self.user_entry.pack()
        
        Label(self, text="Device ID:").pack()
        self.dev_entry = Entry(self); self.dev_entry.pack()

        # Action Buttons
        Button(self, text="1. Initialize Keys (Phase 1)", command=self.do_init).pack(pady=5)
        Button(self, text="2. Register (Phase 1)", command=self.do_register).pack(pady=5)
        Button(self, text="3. Secure Login (Phase 2)", command=self.do_login).pack(pady=5, bg="#ddffdd")
        Button(self, text="4. List Devices (Phase 2)", command=self.do_list).pack(pady=5)

        self.output = scrolledtext.ScrolledText(self, height=10)
        self.output.pack(fill="both", padx=10, pady=10)

    def log(self, msg):
        self.output.insert("end", str(msg) + "\n\n")

    def run_threaded(self, target, *args):
        threading.Thread(target=target, args=args, daemon=True).start()

    def do_init(self):
        pin = simpledialog.askstring("PIN", "Set a PIN:", show="*")
        if pin: 
            # We wrap Phase 1 logic in the GUI
            self.run_threaded(lambda: self.client.init_keys(pin) or self.log("Keys Initialized"))

    def do_register(self):
        u, d = self.user_entry.get(), self.dev_entry.get()
        # We wrap Phase 1 network logic
        self.run_threaded(lambda: self.client.register(u, d) or self.log("Register Request Sent"))

    def do_login(self):
        u, d = self.user_entry.get(), self.dev_entry.get()
        pin = simpledialog.askstring("PIN", "Enter PIN:", show="*")
        if pin:
            # We wrap Phase 2 auth logic
            self.run_threaded(lambda: self.client.login(u, d, pin) or self.log("Login Attempt Finished"))

    def do_list(self):
        u = self.user_entry.get()
        self.run_threaded(lambda: self.client.list_devices(u) or self.log("List Request Sent"))

if __name__ == "__main__":
    ClientGUI().mainloop()
