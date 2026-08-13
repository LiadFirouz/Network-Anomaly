Project Title: AI-Powered Network Intrusion Detection System (IDS)
Technologies: C, Python, libpcap, Pandas, Scikit-Learn (Isolation Forest), Matplotlib, IPC.

Overview:
Developed a hybrid Intrusion Detection System that captures live network traffic at the kernel level and analyzes it in real-time using unsupervised Machine Learning to identify anomalies and cyber threats like stealth port scans.

Key Features & Architecture:

Low-Level Packet Engine: Engineered a high-performance C-based network sniffer utilizing libpcap to capture raw packets, parse TCP/UDP/IP headers, extract flags (SYN), and handle cross-platform endianness.

Real-Time Data Pipeline (IPC): Designed an Inter-Process Communication bridge streaming structured JSON data directly from the C memory space to a Python processor for live dataset generation.

Machine Learning Analytics: Implemented an Isolation Forest model to baseline regular network behavior and detect deviations.

Feature Engineering: Calculated real-time metrics (e.g., Packets Per Second/Time Windows) to combat ML evasion techniques and data poisoning.

Data Visualization: Generated comprehensive Matplotlib scatter plots comparing baseline traffic vs. malicious Nmap SYN scans.

Research Conclusion:
The project demonstrated a critical cybersecurity vulnerability: unsupervised ML models are susceptible to Data Poisoning during high-rate volumetric attacks (like aggressive Nmap scans). It highlights the necessity of combining rule-based heuristics with Machine Learning for a robust, hybrid defense architecture.

Visualizing Data Poisoning in ML:
