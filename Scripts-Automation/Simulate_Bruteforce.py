# save it to a file and remember the location
# go to terminal cd to the file location 
# install python on your computer 
# run the script using <.\filename.py>
# search the logs in splunk in the index you forwaded the logs to 
import time
from datetime import datetime

LOG_FILE = "C:\\splunk_logs\\test.log"

# make sure folder exists
import os
os.makedirs("C:\\splunk_logs", exist_ok=True)

print("Generating logs... Press Ctrl+C to stop")

while True:
    log = f"{datetime.now()} INFO User login failed for user admin from 192.168.1.10"
    with open(LOG_FILE, "a") as f:
        f.write(log + "\n")

    print(log)
    time.sleep(2)
