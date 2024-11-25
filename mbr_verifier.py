import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import win32file
import win32con
import win32api
import os
import struct

class MBRVerifier(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # Backup MBR code (440 bytes)
        self.BACKUP_MBR = bytes.fromhex('33C08ED0BC007C8EC08ED8BE007CBF0006B90002FCF3A450681C06CBFBB90400BDBE07807E00007C0B0F850E0183C510E2F1CD1888560055C6461105C6461000B441BBAA55CD135D720F81FB55AA7509F7C101007403FE46106660807E1000742666680000000066FF760868000068007C680100681000B4428A56008BF4CD139F83C4109EEB14B80102BB007C8A56008A76018A4E028A6E03CD136661731CFE4E11750C807E00800F848A00B280EB845532E48A5600CD135DEB9E813EFE7D55AA756EFF7600E88D007517FAB0D1E664E88300B0DFE660E87C00B0FFE664E87500FBB800BBCD1A6623C0753B6681FB54435041753281F90201722C666807BB00006668000200006668080000006653665366556668000000006668007C0000666168000007CD1A5A32F6EA007C0000CD18A0B707EB08A0B607EB03A0B50732E40500078BF0AC3C007409BB0700B40ECD10EBF2F4EBFD2BC9E464EB002402E0F82402C3496E76616C696420706172746974696F6E207461626C65004572726F72206C6F6164696E67206F7065726174696E672073797374656D004D697373696E67206F7065726174696E672073797374656D000000637B9A')
        self.ORIGINAL_MBR_HASH = "59019b8b59cffb325855cdc7716d38f8ce2112b9b027f2f8516992e2e686525b"
        
        self.setup_gui()
    
    def setup_gui(self):
        self.title("MBR Integrity Verifier and Recovery Tool")
        self.geometry("600x720")
        
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
        
        # Drive selection
        ttk.Label(main_frame, text="Select Drive:").grid(row=2, column=0, pady=5)
        self.drive_var = tk.StringVar(value="0")
        drive_options = self.get_physical_drives()
        self.drive_menu = ttk.Combobox(main_frame, textvariable=self.drive_var, values=drive_options)
        self.drive_menu.grid(row=2, column=1)
        
        # Image path selection
        self.image_path = tk.StringVar()
        ttk.Label(main_frame, text="Image Path:").grid(row=3, column=0, pady=5)
        ttk.Entry(main_frame, textvariable=self.image_path, width=50).grid(row=3, column=1)
        ttk.Button(main_frame, text="Browse", command=self.browse_image).grid(row=3, column=2)
        
        # Action buttons
        ttk.Button(main_frame, text="Verify MBR Integrity", 
                  command=self.verify_mbr).grid(row=4, column=0, pady=20)
        ttk.Button(main_frame, text="Recover MBR", 
                  command=self.recover_mbr).grid(row=4, column=1, pady=20)
        ttk.Button(main_frame, text="Take Partition Table Snapshot", 
                  command=self.take_snapshot).grid(row=5, column=0, pady=10)
        ttk.Button(main_frame, text="Recover Partition Table", 
                  command=self.recover_partition_table).grid(row=5, column=1, pady=10)
        ttk.Button(main_frame, text="Corrupt PT (Test)", 
                  command=self.corrupt_partition_table_for_testing).grid(row=5, column=2, pady=10)
        
        # Results display
        self.result_text = tk.Text(main_frame, height=6, width=65)
        self.result_text.grid(row=6, column=0, columnspan=3, pady=10)
        
        # Hex viewer
        ttk.Label(main_frame, text="MBR Hex Viewer:").grid(row=7, column=0, pady=5)
        self.hex_viewer = tk.Text(main_frame, height=20, width=65)
        self.hex_viewer.grid(row=8, column=0, columnspan=3, pady=10)
    
    def get_physical_drives(self):
        drives = []
        for i in range(10):  # Assuming up to 10 drives
            try:
                handle = win32file.CreateFile(
                    f"\\\\.\\PhysicalDrive{i}",
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                win32file.CloseHandle(handle)
                drives.append(f"PhysicalDrive{i}")
            except Exception:
                pass
        return drives

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
                    f"\\\\.\\{self.drive_var.get()}",
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                mbr_data = win32file.ReadFile(drive_handle, 512)[1]
                win32file.CloseHandle(drive_handle)
                self.display_hex(mbr_data)
                return mbr_data[:440]
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read live MBR: {str(e)}")
                return None
        else:
            try:
                with open(self.image_path.get(), 'rb') as f:
                    mbr_data = f.read(512)
                    self.display_hex(mbr_data)
                    return mbr_data[:440]
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read image MBR: {str(e)}")
                return None

    def display_hex(self, data):
        hex_str = ""
        # Add header row
        hex_str += "Address   " + " ".join(f"{i:02X}" for i in range(16)) + "\n"
        # Add data rows
        for i in range(0, len(data), 16):
            row_data = data[i:i+16]
            hex_str += f"{i:08X}  " + " ".join(f"{byte:02X}" for byte in row_data) + "\n"
        self.hex_viewer.delete(1.0, tk.END)
        self.hex_viewer.insert(tk.END, hex_str)

    def calculate_hash(self, data):
        return hashlib.sha256(data).hexdigest()

    def verify_mbr(self):
        mbr_data = self.read_mbr()
        if mbr_data:
            current_hash = self.calculate_hash(mbr_data)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Current MBR Hash:\n{current_hash}\n")
            self.result_text.insert(tk.END, f"Original MBR Hash:\n{self.ORIGINAL_MBR_HASH}\n")
            
            if current_hash == self.ORIGINAL_MBR_HASH:
                self.result_text.insert(tk.END, "Status: MBR is intact ✓")
            else:
                self.result_text.insert(tk.END, "Status: MBR integrity check failed ✗")

    def recover_mbr(self):
        if self.source_var.get() == "live":
            try:
                # Check admin rights
                import ctypes
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    messagebox.showerror("Error", "Administrator privileges required")
                    return
                    
                drive_handle = win32file.CreateFile(
                    f"\\\\.\\{self.drive_var.get()}",
                    win32con.GENERIC_WRITE,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                
                # Write MBR data
                win32file.WriteFile(drive_handle, self.BACKUP_MBR[:440])
                win32file.CloseHandle(drive_handle)
                
                messagebox.showinfo("Success", "MBR has been recovered successfully")
                self.verify_mbr()
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to recover MBR: {str(e)}")
        else:
            # Handle image recovery
            try:
                image_path = self.image_path.get()
                if not image_path:
                    messagebox.showerror("Error", "Please select an image file")
                    return
                
                if not os.path.exists(image_path):
                    messagebox.showerror("Error", "Image file not found")
                    return
                
                # Create backup
                backup_path = image_path + ".backup"
                if not os.path.exists(backup_path):
                    import shutil
                    shutil.copy2(image_path, backup_path)
                
                # Write MBR to image
                with open(image_path, 'r+b') as f:
                    f.seek(0)
                    f.write(self.BACKUP_MBR[:440])
                
                messagebox.showinfo("Success", 
                                    f"MBR recovered successfully.\nBackup created at: {backup_path}")
                self.verify_mbr()
                
            except PermissionError:
                messagebox.showerror("Error", "Permission denied. Run as administrator.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to recover image MBR: {str(e)}")

    def take_snapshot(self):
        if self.source_var.get() == "live":
            try:
                drive_handle = win32file.CreateFile(
                    f"\\\\.\\{self.drive_var.get()}",
                    win32con.GENERIC_READ,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                    None,
                    win32con.OPEN_EXISTING,
                    0,
                    None
                )
                mbr_data = win32file.ReadFile(drive_handle, 512)[1]
                win32file.CloseHandle(drive_handle)
                with open(f'{self.drive_var.get()}_partition_table_snapshot.bin', 'wb') as f:
                    f.write(mbr_data[446:510])  # Partition table is 64 bytes starting at offset 446
                messagebox.showinfo("Success", "Partition table snapshot taken successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to take snapshot: {str(e)}")
        else:
            try:
                with open(self.image_path.get(), 'rb') as f:
                    f.seek(446)
                    partition_table = f.read(64)
                with open(f'{self.image_path.get()}_partition_table_snapshot.bin', 'wb') as f:
                    f.write(partition_table)
                messagebox.showinfo("Success", "Partition table snapshot taken successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to take snapshot: {str(e)}")

    def recover_partition_table(self):
        try:
            # Validate we're in image mode
            if self.source_var.get() != "image":
                messagebox.showerror("Error", "Please switch to forensic image mode")
                return

            # Check if image path exists
            if not self.image_path.get():
                messagebox.showerror("Error", "No image file selected")
                return

            # Validate snapshot file exists
            snapshot_file = f'{self.image_path.get()}_partition_table_snapshot.bin'
            if not os.path.exists(snapshot_file):
                messagebox.showerror("Error", "Partition table snapshot not found")
                return

            # Read partition table from snapshot
            with open(snapshot_file, 'rb') as f:
                partition_table = f.read(64)

            # Validate partition table size
            if len(partition_table) != 64:
                messagebox.showerror("Error", "Invalid partition table data")
                return

            # Write partition table back to image
            with open(self.image_path.get(), 'r+b') as f:
                f.seek(446)  # Partition table offset
                f.write(partition_table)

            messagebox.showinfo("Success", "Partition table recovered successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to recover partition table: {str(e)}")

    def corrupt_partition_table_for_testing(self):
        """Test function to write random data to partition table area of forensic image"""
        try:
            # Ensure we're working with an image file, not live disk
            if self.source_var.get() != "image":
                messagebox.showerror("Error", "Please select a forensic image first")
                return
                
            image_path = self.image_path.get()
            if not image_path:
                messagebox.showerror("Error", "No image file selected")
                return
                
            # Create backup before testing
            backup_path = image_path + ".testing_backup"
            import shutil
            shutil.copy2(image_path, backup_path)
            
            # Generate random test data
            import random
            random_data = bytes([random.randint(0, 255) for _ in range(64)])
            
            # Write random data to partition table area
            with open(image_path, 'r+b') as f:
                f.seek(446)  # Partition table offset
                f.write(random_data)
                
            messagebox.showinfo("Success", 
                "Partition table corrupted for testing.\n" +
                f"Backup saved at: {backup_path}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Test corruption failed: {str(e)}")

if __name__ == "__main__":
    app = MBRVerifier()
    app.mainloop()