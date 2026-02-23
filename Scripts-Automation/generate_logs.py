import time
import random
import datetime

# Professional tip: Use a list of common IT events
events = [
    "INFO - User login successful for: admin",
    "WARN - High CPU usage detected: 85%",
    "ERROR - Connection timeout on database_srv",
    "INFO - Backup process started",
    "ERROR - Unauthorized access attempt from IP: 192.168.1.50"
]

def generate_log():
    with open("datasets/live_system_activity.log", "a") as f:
        while True:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            event = random.choice(events)
            log_entry = f"{timestamp} {event}\n"
            f.write(log_entry)
            print(f"Generated: {log_entry.strip()}")
            f.flush()
            time.sleep(random.randint(2, 10)) # Simulate random activity

if __name__ == "__main__":
    print("Starting IT Operations Log Generator...")
    generate_log()
