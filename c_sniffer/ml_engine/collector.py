import subprocess
import json
import pandas as pd
from datetime import datetime
import sys

# Define the command to run the C Sniffer
SNIFFER_CMD = ["sudo", "../sniffer", "en0"]
def start_collector():
    print(f"[*] Starting C Packet Sniffer Pipeline: {' '.join(SNIFFER_CMD)}")
    
    try:
        # Start the C Sniffer process. Small change: redirecting stderr to stdout to capture system errors
        process = subprocess.Popen(
            SNIFFER_CMD, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True
        )

        packet_data_list = []
        packet_count = 0

        for line in iter(process.stdout.readline, ''):
            line = line.strip()
            if not line:
                continue
            
            # If the line is a JSON object, process it
            if line.startswith('{') and line.endswith('}'):
                try:
                    packet_dict = json.loads(line)
                    packet_dict['timestamp'] = datetime.now().isoformat()
                    
                    packet_data_list.append(packet_dict)
                    packet_count += 1
                    
                    if packet_count % 10 == 0:
                        print(f"[Python] Collected {packet_count} packets in real-time...")
                        
                except json.JSONDecodeError:
                    print(f"[!] JSON Error parsing line: {line}")
            else:
                # Added this block! If it's an error or a C startup message, print it to the screen
                print(f"[C Process]: {line}")

        # If execution reaches here, it means the C Sniffer process terminated for some reason
        print("\n[!] The C Sniffer process terminated unexpectedly.")

    except KeyboardInterrupt:
        print("\n[*] Stopping collector and saving data...")
    
    # Save the collected data to a Pandas DataFrame before exiting
    if packet_count > 0:
        df = pd.DataFrame(packet_data_list)
        df.to_csv("network_traffic.csv", index=False)
        print(f"[*] Saved {len(df)} packets to 'network_traffic.csv'.")
    else:
        print("[*] No packets collected to save.")
        
    try:
        process.terminate()
    except Exception:
        pass

if __name__ == "__main__":
    start_collector()