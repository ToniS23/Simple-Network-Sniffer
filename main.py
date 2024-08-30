import sys
import io
from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext
import threading

main = tk.Tk()

main.title("Simple Packet Sniffer")

main.geometry("800x700")
main.resizable(False, False)

output_text = scrolledtext.ScrolledText(main, width=80, height=30, wrap=tk.WORD)
output_text.pack(padx=10, pady=10)

def capture_packets():
    old_stdout = sys.stdout
    sys.stdout = captured_output = io.StringIO()
    try:
        packets = sniff(count=10)
        packets.show()
        output_text.insert(tk.END, captured_output.getvalue())
        output_text.see(tk.END)
    finally:
        sys.stdout = old_stdout

def start_capture():
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start()
    

update_button = tk.Button(main, text='Capture 10 packets :)', command=start_capture)
update_button.pack(pady=10)

main.mainloop()