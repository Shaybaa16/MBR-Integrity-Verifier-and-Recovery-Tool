import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

# Hardcoded hash value of the known good MBR
KNOWN_GOOD_MBR = bytes.fromhex(
    "33C08ED0BC007C8EC08ED8BE007CBF0006B90002FCF3A450681C06CBFBB90400BDBE07807E00007C0B0F850E0183C510E2F1CD1888560055C6461105C6461000B441BBAA55CD135D720F81FB55AA7509F7C101007403FE46106660807E1000742666680000000066FF760868000068007C680100681000B4428A56008BF4CD139F83C4109EEB14B80102BB007C8A56008A76018A4E028A6E03CD136661731CFE4E11750C807E00800F848A00B280EB845532E48A5600CD135DEB9E813EFE7D55AA756EFF7600E88D007517FAB0D1E664E88300B0DFE660E87C00B0FFE664E87500FBB800BBCD1A6623C0753B6681FB54435041753281F90201722C666807BB00006668000200006668080000006653665366556668000000006668007C0000666168000007CD1A5A32F6EA007C0000CD18A0B707EB08A0B607EB03A0B50732E40500078BF0AC3C007409BB0700B40ECD10EBF2F4EBFD2BC9E464EB002402E0F82402C3496E76616C696420706172746974696F6E207461626C65004572726F72206C6F6164696E67206F7065726174696E672073797374656D004D697373696E67206F7065726174696E672073797374656D000000637B9A"
)
KNOWN_GOOD_HASH=hashlib.sha256(KNOWN_GOOD_MBR).hexdigest()
print(KNOWN_GOOD_HASH)
print(KNOWN_GOOD_MBR)

# Function to read MBR from a live system
def read_mbr_live():
    try:
        with open(r"\\.\PhysicalDrive1", "rb") as f:
            mbr = f.read(440)
        return mbr
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read MBR: {e}")
        return None

# Function to read MBR from a forensic image
def read_mbr_image(file_path):
    try:
        with open(file_path, "rb") as f:
            mbr = f.read(440)
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
        with open(r"\\.\PhysicalDrive1", "wb") as f:
            f.write(KNOWN_GOOD_MBR)
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