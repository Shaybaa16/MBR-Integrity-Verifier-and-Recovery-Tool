# MBR Integrity Verifier and Recovery Tool

A robust tool for verifying and recovering the Master Boot Record (MBR) to ensure system integrity and reliability. This project leverages Python to provide a seamless way to monitor and restore critical system data. It supports Windows platforms and forensic images in raw data format with the `.002` extension.

## Table of Contents
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Usage](#usage)
- [Code Snippets](#code-snippets)
- [Contribution](#contribution)
- [License](#license)

## Dependencies

This project requires the following dependencies, listed in [`requirements.txt`](requirements.txt ):
- Python 3.6 or higher
- pip (Python package manager)
- `pywin32` for Windows-specific operations
- `tkinter` for GUI

You can install all required packages after setting up the project. See the Installation section for details.

## Installation

Follow these steps to install and set up the **MBR Integrity Verifier and Recovery Tool**:

1. Clone the repository:
   ```bash
   git clone https://github.com/Shaybaa16/MBR-Integrity-Verifier-and-Recovery-Tool.git
   ```
2. Navigate to the project folder:
   ```bash
   cd MBR-Integrity-Verifier-and-Recovery-Tool
   ```

3. Create a virtual environment:
   ```bash
   python -m venv venv
   ```

4. Activate the virtual environment:
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```
5. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

That's it! The tool is now set up and ready to use.

## Usage

To use the tool, simply run the Python script:

```bash
python mbr_verifier.py
```

Follow the prompts to verify or recover the MBR on your system.

## Code Snippets

### Verifying MBR Integrity

The `verify_mbr` method reads the MBR data and compares its hash with the original hash:

```python
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
```

### Recovering MBR

The `recover_mbr` method restores the MBR from a backup:

```python
def recover_mbr(self):
    if self.source_var.get() == "live":
        try:
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
            
            win32file.WriteFile(drive_handle, self.BACKUP_MBR[:440])
            win32file.CloseHandle(drive_handle)
            
            messagebox.showinfo("Success", "MBR has been recovered successfully")
            self.verify_mbr()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to recover MBR: {str(e)}")
    else:
        try:
            image_path = self.image_path.get()
            if not image_path:
                messagebox.showerror("Error", "Please select an image file")
                return
                
            if not os.path.exists(image_path):
                messagebox.showerror("Error", "Image file not found")
                return
                
            backup_path = image_path + ".backup"
            if not os.path.exists(backup_path):
                import shutil
                shutil.copy2(image_path, backup_path)
                
            with open(image_path, 'r+b') as f:
                f.seek(0)
                f.write(self.BACKUP_MBR[:440])
                
            messagebox.showinfo("Success", f"MBR recovered successfully.\nBackup created at: {backup_path}")
            self.verify_mbr()
            
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Run as administrator.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to recover image MBR: {str(e)}")
```

## Contribution

Contributions are welcome! Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -am 'Add new feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Create a new Pull Request.

## License

This project is licensed under the [MIT License](./LICENSE).