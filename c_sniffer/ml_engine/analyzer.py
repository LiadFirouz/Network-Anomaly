import pandas as pd
from sklearn.ensemble import IsolationForest

def analyze_and_detect(csv_file):
    print(f"[*] Loading data from '{csv_file}'...")
    
    try:
        df = pd.read_csv(csv_file)
        print(f"[*] Successfully loaded {len(df)} packets.\n")
        
        # 1. Feature Engineering: Selecting only numerical columns for the model
        # An AI model does not read IP addresses as text, but relies on numerical features
        features = ['src_port', 'dst_port', 'protocol', 'length', 'is_syn']
        X = df[features]
        
        print("[*] Training Isolation Forest ML Model...")
        # 2. Building the model: 'contamination' tells the model what percentage of the traffic we estimate to be malicious (e.g., 5%)
        model = IsolationForest(contamination=0.05, random_state=42)
        
        # 3. Training the model and classifying the packets
        # The model returns 1 for a normal packet, and -1 for an anomaly!
        df['anomaly_score'] = model.fit_predict(X)
        
        # 4. Filtering and displaying only the anomalies
        anomalies = df[df['anomaly_score'] == -1]
        
        print("\n==================================================")
        print("              [!] ML ANALYSIS RESULTS             ")
        print("==================================================")
        
        if len(anomalies) > 0:
            print(f"[!] ALERT: FOUND {len(anomalies)} SUSPICIOUS PACKETS (ANOMALIES):\n")
            # Print the suspicious packets cleanly
            print(anomalies[['src_ip', 'dst_ip', 'protocol', 'length', 'is_syn']])
        else:
            print("[*] Network looks completely clean. No anomalies detected.")
            
    except FileNotFoundError:
        print(f"[!] Error: File '{csv_file}' not found.")

if __name__ == "__main__":
    analyze_and_detect("network_traffic.csv")