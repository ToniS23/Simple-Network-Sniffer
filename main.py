import sys
import io
from scapy.all import *
import tkinter as tk
from tkinter import scrolledtext
import threading
from tkinter import ttk
import dns_info_requests

main = tk.Tk()

main.title("Simple Network Sniffer")

main.geometry("900x700")
main.resizable(False, False)

# create tabs
notebook = ttk.Notebook(main)
notebook.pack(expand=True, fill='both')
tab1 = ttk.Frame(notebook)
tab2 = ttk.Frame(notebook)
notebook.add(tab1, text='Packet Capture')
notebook.add(tab2, text='DNS info')

# insert icon
main.iconbitmap("./sniffing-dog.ico")

# frame for the title
title_frame = tk.Frame(tab1)
title_frame.pack(padx=10, pady=10)

# title management (logo+title)
image = tk.PhotoImage(file="./sniffing-dog.png")
image_label = tk.Label(title_frame, image=image, width=60, height=60)
image_label.pack(side=tk.LEFT, padx=10)
title_label = tk.Label(title_frame, text="Simple Network Sniffer", font=("Arial", 20, "bold"))
title_label.pack(side=tk.LEFT, padx=10)

# main widget management
output_text = scrolledtext.ScrolledText(tab1, width=100, height=30, wrap=tk.WORD) # main widget
output_text.pack(padx=10, pady=10)

captured_packets = None

def capture_packets():
    global captured_packets
    old_stdout = sys.stdout
    sys.stdout = captured_output = io.StringIO()

    try:
        # starting message
        output_text.insert(tk.END, "[+]-Capturing packets, please wait....\n")

        # capture the packets
        captured_packets = sniff(count=10) # this will block the event loop because it doesn't return control only after it captures packets
        captured_packets.show() # this is NOT returned as a string but as stdoutput so it can't be output to the widget

        # show captured packets in widget
        output_text.insert(tk.END, captured_output.getvalue()) # send the value of the StringIO object to the widget
        output_text.see(tk.END)

    except BaseException:
        print("Unexpected Error") # for handling anything that could go wrong

    finally:
        sys.stdout = old_stdout # restore old stdoutput

# function for details of packages
def show_details():
    if captured_packets:
        output_text.insert(tk.END, "[+]-Loading details, please wait....\n")
        for i,packet in enumerate(captured_packets):
            output_text.insert(tk.END, f"Packet.... {i}: {packet.summary()}\n")
            output_text.insert(tk.END, f"Details.... \n {packet.show(dump=True)}\n\n")
            output_text.see(tk.END)
    else:
        output_text.insert(tk.END, "[+]-No packets captured yet.... \n")

# we need this function to not block the main thread on which our UI runs (event loop)
def start_capture():
    output_text.insert(tk.END, "[+]-Capturing packets, please wait....\n")
    capture_thread = threading.Thread(target=capture_packets)
    capture_thread.start() # start the separate thread for capturing packets

# separate thread for details
def details_thread():
    details_thread = threading.Thread(target=show_details)   
    details_thread.start() # start the separate thread for capturing packets

button_frame = tk.Frame(tab1)
button_frame.pack(padx=10, pady=10)

update_button = tk.Button(button_frame, text='Capture 10 packets :)', command=start_capture)
update_button.pack(side=tk.LEFT, padx=10 ,pady=10)
show_packets_details_button = tk.Button(button_frame, text='Show Details', command=details_thread)
show_packets_details_button.pack(side=tk.LEFT, padx=10 ,pady=10)

# function that processes the input and returns some output
def process_input():
    user_input = input_box.get()  # get the text from the input box
    result = dns_info_requests.get_dns_info(str(user_input)) # get the DNS info as a string
    output_box.config(state=tk.NORMAL)  # enable the output box to update the text
    output_box.delete(1.0, tk.END)  # clear the output box
    output_box.insert(tk.END, result)  # insert the result into the output box
    output_box.config(state=tk.DISABLED)  # disable the output box again

output_box = tk.Text(tab2, width=50, height=30, state=tk.DISABLED)
output_box.pack(pady=20)

dns_label = tk.Label(tab2, text="Input IP Address (leave blank for your own IP)", font=("Arial", 10, "bold"))
dns_label.pack(padx=0, pady=0)

dns_info_frame = tk.Frame(tab2)
dns_info_frame.pack(padx=10, pady=10)

input_box = tk.Entry(dns_info_frame, width=30)
input_box.pack(side=tk.LEFT, padx=10 ,pady=10)

process_button = tk.Button(dns_info_frame, text="GET", command=process_input, width=10)
process_button.pack(side=tk.LEFT, padx=10 ,pady=10)

main.mainloop()