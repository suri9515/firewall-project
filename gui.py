import tkinter as tk
from scapy.all import sniff
from threading import Thread

class FirewallGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Firewall Monitor")
        self.text = tk.Text(self.root, height=30, width=100)
        self.text.pack()
        self.running = True

    def update_display(self, packet):
        self.text.insert(tk.END, packet.summary() + "\n")
        self.text.see(tk.END)

    def start_sniffing(self):
        sniff(prn=self.update_display, store=0)

    def run(self):
        t = Thread(target=self.start_sniffing)
        t.daemon = True
        t.start()
        self.root.mainloop()

if __name__ == "__main__":
    app = FirewallGUI()
    app.run()
