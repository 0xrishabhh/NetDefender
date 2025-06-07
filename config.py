import os

# Directory to monitor for new files
WATCH_FOLDER = "C:/Your_PATH TO MONITOR"

# Path to ClamAV scan command
CLAMSCAN_PATH = "C:/....../ClamAV/clamscan.exe"

# Log file for scan results
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "scan_logs.txt")

# What to do when a virus is found? (Options: "delete", "move", "log_only")
ACTION_ON_VIRUS = "delete"

# If moving infected files, specify the quarantine folder
QUARANTINE_FOLDER = "C:/..../Quarantine"

# Ensure required directories exist
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)  # Create logs directory
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)  # Create quarantine directory if action is "move"

# Additional configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB - maximum file size to scan
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
    'zip', 'rar', '7z', 'tar', 'gz',
    'exe', 'dll', 'sys',
    'jpg', 'jpeg', 'png', 'gif'
}

# Scan settings
SCAN_SETTINGS = {
    'recursive': True,           # Scan directories recursively
    'scan_archives': True,       # Scan inside archive files
    'max_scansize': MAX_FILE_SIZE,
    'max_filesize': MAX_FILE_SIZE,
    'max_scantime': 300,        # Maximum scan time per file (in seconds)
    'database': os.path.join(os.path.dirname(CLAMSCAN_PATH), "database"),  # Path to virus database
} 