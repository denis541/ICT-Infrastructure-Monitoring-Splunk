import os
import shutil
import datetime

# Path where your Splunk is installed (Change this to your actual path)
SPLUNK_CONF_DIR = r"C:\Program Files\Splunk\etc\system\local"
BACKUP_DIR = r"C:\Splunk_Backups"

def run_backup():
    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        
    date_str = datetime.datetime.now().strftime("%Y-%m-%d")
    destination = os.path.join(BACKUP_DIR, f"splunk_config_backup_{date_str}")
    
    try:
        shutil.copytree(SPLUNK_CONF_DIR, destination)
        print(f"Successfully backed up Splunk configs to: {destination}")
    except Exception as e:
        print(f"Backup failed: {e}")

if __name__ == "__main__":
    run_backup()
