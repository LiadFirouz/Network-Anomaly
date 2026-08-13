import pandas as pd
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

def extract_time_features(df):
    """
    A function that takes the data, reads the timestamp,
    and calculates the packet rate (Packets per second) to give the model a "sense of time".
    """
    # Convert the text column to a real datetime object
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Sort the data by time
    df = df.sort_values('timestamp')
    
    # Calculation: how many packets were received in a 1-second rolling window?
    df.set_index('timestamp', inplace=True)
    df['packet_rate'] = df['is_syn'].rolling('1s').count()
    df.reset_index(inplace=True)
    
    # Fill empty cells (if any) with 1
    df['packet_rate'] = df['packet_rate'].fillna(1)
    return df

def train_and_detect_with_time(clean_csv, attack_csv):
    print("[*] Loading data and engineering TIME features...")
    try:
        df_clean = pd.read_csv(clean_csv)
        df_attack = pd.read_csv(attack_csv)
    except FileNotFoundError as e:
        print(f"[!] Error loading files: {e}")
        return
        
    # --- Add the time dimension to the data ---
    df_clean = extract_time_features(df_clean)
    df_attack = extract_time_features(df_attack)
    
    # Note! We added 'packet_rate' to the list of features the model learns
    features = ['src_port', 'dst_port', 'protocol', 'length', 'is_syn', 'packet_rate']
    
    X_clean = df_clean[features]
    X_attack = df_attack[features]
    
    print("[*] Training Isolation Forest on CLEAN Baseline (Time-Aware)...")
    # Train on the clean data
    model = IsolationForest(contamination=0.01, random_state=42)
    model.fit(X_clean)
    
    print("[*] Analyzing Attack Traffic...")
    # Predict on the attack file
    df_attack['anomaly_score'] = model.predict(X_attack)
    
    print("[*] Generating Data Visualization...")
    
    # --- Drawing the graph ---
    plt.figure(figsize=(12, 6))
    
    normal = df_attack[df_attack['anomaly_score'] == 1]
    plt.scatter(normal.index, normal['dst_port'], color='dodgerblue', label='Normal Traffic', alpha=0.3, s=15)
    
    anomalies = df_attack[df_attack['anomaly_score'] == -1]
    plt.scatter(anomalies.index, anomalies['dst_port'], color='red', label='AI Detected Anomalies', alpha=0.8, s=35)
    
    syn_packets = df_attack[df_attack['is_syn'] == 1]
    plt.scatter(syn_packets.index, syn_packets['dst_port'], color='yellow', label='Actual SYN Packets (Nmap)', marker='*', edgecolor='black', s=80)

    plt.title("Network Traffic Analysis: Time-Aware AI Catching Nmap Scan")
    plt.xlabel("Timeline (Packet Number)")
    plt.ylabel("Destination Port")
    plt.legend(loc='upper right')
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    
    plt.show()

if __name__ == "__main__":
    train_and_detect_with_time("clean_traffic.csv", "attack_traffic.csv")