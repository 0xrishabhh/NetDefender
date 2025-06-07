import subprocess
import os
import shutil
from datetime import datetime
from config import (
    CLAMSCAN_PATH, LOG_FILE, ACTION_ON_VIRUS, QUARANTINE_FOLDER,
    SCAN_SETTINGS, ALLOWED_EXTENSIONS, MAX_FILE_SIZE
)

class VirusScanner:
    @staticmethod
    def is_file_allowed(filename):
        """Check if the file extension is allowed for scanning."""
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    @staticmethod
    def is_file_size_allowed(file_path):
        """Check if the file size is within the allowed limit."""
        return os.path.getsize(file_path) <= MAX_FILE_SIZE

    def handle_infected_file(self, file_path, threat_name):
        """Handle infected file based on ACTION_ON_VIRUS setting."""
        try:
            if ACTION_ON_VIRUS == "delete":
                os.remove(file_path)
                action_taken = "Deleted"
            elif ACTION_ON_VIRUS == "move":
                # Create a subfolder in quarantine using current timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                quarantine_subfolder = os.path.join(QUARANTINE_FOLDER, timestamp)
                os.makedirs(quarantine_subfolder, exist_ok=True)
                
                # Move the file to quarantine with metadata
                shutil.move(file_path, os.path.join(quarantine_subfolder, os.path.basename(file_path)))
                
                # Create metadata file
                with open(os.path.join(quarantine_subfolder, "metadata.txt"), "w") as f:
                    f.write(f"Original location: {file_path}\n")
                    f.write(f"Quarantine date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Threat detected: {threat_name}\n")
                
                action_taken = "Quarantined"
            else:  # log_only
                action_taken = "Logged only"
            
            return action_taken
        except Exception as e:
            return f"Failed to handle infected file: {str(e)}"

    @staticmethod
    def scan_file(file_path):
        """Scan a single file using ClamAV."""
        print(f"🔍 Scanning file: {file_path}")
        result = subprocess.run([CLAMSCAN_PATH, file_path], capture_output=True, text=True)
        
        with open(LOG_FILE, "a") as log:
            log.write(result.stdout + "\n")
        
        if "FOUND" in result.stdout:
            print(f"⚠️ VIRUS DETECTED in {file_path}!")
            return {
                "success": True,
                "is_infected": True,
                "message": f"⚠️ VIRUS DETECTED in {file_path}!"
            }
        else:
            print(f"✅ File is clean: {file_path}")
            return {
                "success": True,
                "is_infected": False,
                "message": "✅ File is clean"
            }

    @staticmethod
    def scan_folder(folder_path):
        """Scan an entire folder recursively."""
        print(f"🔍 Scanning folder: {folder_path}")
        result = subprocess.run([CLAMSCAN_PATH, "--recursive", folder_path], capture_output=True, text=True)
        
        with open(LOG_FILE, "a") as log:
            log.write(result.stdout + "\n")

        print(result.stdout)
        return {
            "success": True,
            "output": result.stdout,
            "message": "Folder scan completed"
        }

    @staticmethod
    def get_version():
        """Get ClamAV version."""
        try:
            result = subprocess.run([CLAMSCAN_PATH, "--version"], capture_output=True, text=True)
            return result.stdout.split("\n")[0]
        except Exception as e:
            return f"Error getting version: {str(e)}"

# Create functions that use the VirusScanner class
def scan_file(file_path):
    """Wrapper function for scanning a single file"""
    scanner = VirusScanner()
    return scanner.scan_file(file_path)

def scan_folder(folder_path):
    """Wrapper function for scanning a folder"""
    scanner = VirusScanner()
    return scanner.scan_folder(folder_path)

if __name__ == "__main__":
    folder_to_scan = input("Enter the folder path to scan: ")
    if os.path.exists(folder_to_scan):
        scan_folder(folder_to_scan)
    else:
        print("❌ Invalid folder path.") 