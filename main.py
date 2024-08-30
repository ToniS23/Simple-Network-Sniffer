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

output_text = scrolledtext.ScrolledText(main, width=80, height=30, wrap=tk.WORD) # main widget
output_text.pack(padx=10, pady=10)

def capture_packets():
    old_stdout = sys.stdout
    sys.stdout = captured_output = io.StringIO()
    try:
        packets = sniff(count=10) # this will block the event loop because it doesn't return control only after it captures packets
        packets.show() # this is NOT returned as a string so it can't be output to the widget
        output_text.insert(tk.END, captured_output.getvalue()) # send the value of the StringIO object to the widget
        output_text.see(tk.END)
    finally:
        sys.stdout = old_stdout # restore old stdoutput

# we need this function to not block the main thread on which our UI runs (event loop)
def start_capture():
    output_text.insert(tk.END, "[+]-Capturing packets, please wait....\n")
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start() # start the separate thread for capturing packets
    

update_button = tk.Button(main, text='Capture 10 packets :)', command=start_capture)
update_button.pack(pady=20)

main.mainloop()