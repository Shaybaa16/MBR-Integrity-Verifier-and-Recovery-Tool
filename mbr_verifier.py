import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
import subprocess

# Hardcoded hash value of the known good MBR
KNOWN_GOOD_HASH = "good_mbr_hash"

# Function to read MBR from a live system
def read_mbr_live():
    try:
        with open("/dev/nvme0n1", "rb") as f:
            mbr = f.read(512)
        return mbr
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read MBR: {e}")
        return None

# Function to read MBR from a forensic image
def read_mbr_image(file_path):
    try:
        with open(file_path, "rb") as f:
            mbr = f.read(512)
        return mbr
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read MBR: {e}")
        return None

# Function to calculate the hash of the MBR
def calculate_hash(mbr):
    return hashlib.sha256(mbr).hexdigest()

# Function to verify the integrity of the MBR
def verify_integrity(mbr):
    mbr_hash = calculate_hash(mbr)
    return mbr_hash == KNOWN_GOOD_HASH

# Function to recover the MBR
def recover_mbr():
    try:
        # Replace with the path to your known good MBR code
        with open("known_good_mbr.bin", "rb") as f:
            good_mbr = f.read(512)
        with open("/dev/nvme0n1", "wb") as f:
            f.write(good_mbr)
        messagebox.showinfo("Success", "MBR recovered successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to recover MBR: {e}")

# Function to handle the verification process
def handle_verification(source):
    if source == "live":
        mbr = read_mbr_live()
    else:
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        mbr = read_mbr_image(file_path)
    
    if mbr:
        if verify_integrity(mbr):
            messagebox.showinfo("Integrity Check", "MBR integrity is valid.")
        else:
            messagebox.showwarning("Integrity Check", "MBR integrity is invalid.")
            if messagebox.askyesno("Recover MBR", "Do you want to recover the MBR?"):
                recover_mbr()
                # Reverify after recovery
                mbr = read_mbr_live() if source == "live" else read_mbr_image(file_path)
                if verify_integrity(mbr):
                    messagebox.showinfo("Integrity Check", "MBR integrity is valid after recovery.")
                else:
                    messagebox.showerror("Integrity Check", "MBR integrity is still invalid after recovery.")

# Create the GUI
root = tk.Tk()
root.title("MBR Integrity Verifier and Recovery Tool")

live_button = tk.Button(root, text="Verify Live System MBR", command=lambda: handle_verification("live"))
live_button.pack(pady=10)

image_button = tk.Button(root, text="Verify Forensic Image MBR", command=lambda: handle_verification("image"))
image_button.pack(pady=10)

root.mainloop()