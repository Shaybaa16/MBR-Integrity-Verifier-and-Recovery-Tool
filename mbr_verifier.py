import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import win32file
import win32con
import os
import struct

class MBRVerifier(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # Backup MBR code (440 bytes)
        self.BACKUP_MBR = b'''33C08ED0BC007C8EC08ED8BE007CBF0006B90002FCF3A450681C06CBFBB90400BDBE07807E00007C0B0F850E0183C510E2F1CD1888560055C6461105C6461000B441BBAA55CD135D720F81FB55AA7509F7C101007403FE46106660807E1000742666680000000066FF760868000068007C680100681000B4428A56008BF4CD139F83C4109EEB14B80102BB007C8A56008A76018A4E028A6E03CD136661731CFE4E11750C807E00800F848A00B280EB845532E48A5600CD135DEB9E813EFE7D55AA756EFF7600E88D007517FAB0D1E664E88300B0DFE660E87C00B0FFE664E87500FBB800BBCD1A6623C0753B6681FB54435041753281F90201722C666807BB00006668000200006668080000006653665366556668000000006668007C0000666168000007CD1A5A32F6EA007C0000CD18A0B707EB08A0B607EB03A0B50732E40500078BF0AC3C007409BB0700B40ECD10EBF2F4EBFD2BC9E464EB002402E0F82402C3496E76616C696420706172746974696F6E207461626C65004572726F72206C6F6164696E67206F7065726174696E672073797374656D004D697373696E67206F7065726174696E672073797374656D000000637B9A'''
        # self.ORIGINAL_MBR_HASH = hashlib.sha256(self.BACKUP_MBR[:440]).hexdigest()
        self.ORIGINAL_MBR_HASH = "59019b8b59cffb325855cdc7716d38f8ce2112b9b027f2f8516992e2e686525b"
        # print(f"Original MBR Hash: {self.ORIGINAL_MBR_HASH}")
        
        self.setup_gui()
    
    def setup_gui(self):
        self.title("MBR Integrity Verifier and Recovery Tool")
        self.geometry("600x400")
        
        # Create main frame
        main_frame = ttk.Frame(self, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Source selection
        ttk.Label(main_frame, text="Select Source:").grid(row=0, column=0, pady=5)
        self.source_var = tk.StringVar(value="live")
        ttk.Radiobutton(main_frame, text="Live System", variable=self.source_var, 
                       value="live").grid(row=1, column=0)
        ttk.Radiobutton(main_frame, text="Forensic Image", variable=self.source_var, 
                       value="image").grid(row=1, column=1)
        
        # Image path selection
        self.image_path = tk.StringVar()
        ttk.Label(main_frame, text="Image Path:").grid(row=2, column=0, pady=5)
        ttk.Entry(main_frame, textvariable=self.image_path, width=50).grid(row=2, column=1)
        ttk.Button(main_frame, text="Browse", command=self.browse_image).grid(row=2, column=2)
        
        # Action buttons
        ttk.Button(main_frame, text="Verify MBR Integrity", 
                  command=self.verify_mbr).grid(row=3, column=0, pady=20)
        ttk.Button(main_frame, text="Recover MBR", 
                  command=self.recover_mbr).grid(row=3, column=1, pady=20)
        
        # Results display
        self.result_text = tk.Text(main_frame, height=10, width=60)
        self.result_text.grid(row=4, column=0, columnspan=3, pady=10)

    def browse_image(self):
        filename = filedialog.askopenfilename(
            title="Select Forensic Image",
            filetypes=(("Raw Image", "*.dd *.raw *.img"), ("All Files", "*.*"))
        )
        self.image_path.set(filename)

    def read_mbr(self):
        if self.source_var.get() == "live":
            try:
                drive_handle = win32file.CreateFile(
                    "\\\\.\\PhysicalDrive1",
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                mbr_data = win32file.ReadFile(drive_handle, 512)[1]
                win32file.CloseHandle(drive_handle)
                return mbr_data[:440]
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read live MBR: {str(e)}")
                return None
        else:
            try:
                with open(self.image_path.get(), 'rb') as f:
                    return f.read(440)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read image MBR: {str(e)}")
                return None

    def calculate_hash(self, data):
        return hashlib.sha256(data).hexdigest()

    def verify_mbr(self):
        mbr_data = self.read_mbr()
        if mbr_data:
            current_hash = self.calculate_hash(mbr_data)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Current MBR Hash: {current_hash}\n")
            self.result_text.insert(tk.END, f"Original MBR Hash: {self.ORIGINAL_MBR_HASH}\n")
            
            if current_hash == self.ORIGINAL_MBR_HASH:
                self.result_text.insert(tk.END, "Status: MBR is intact ✓")
            else:
                self.result_text.insert(tk.END, "Status: MBR integrity check failed ✗")

    def recover_mbr(self):
        if self.source_var.get() == "live":
            try:
                drive_handle = win32file.CreateFile(
                    "\\\\.\\PhysicalDrive1",
                    win32con.GENERIC_WRITE,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                win32file.WriteFile(drive_handle, self.BACKUP_MBR)
                win32file.CloseHandle(drive_handle)
                messagebox.showinfo("Success", "MBR has been recovered successfully")
                self.verify_mbr()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to recover MBR: {str(e)}")
        else:
            messagebox.showwarning("Warning", "Recovery is only available for live system")

if __name__ == "__main__":
    app = MBRVerifier()
    app.mainloop()