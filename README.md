# Intrusion Detection System (IDS) Project

## Overview

This project implements a multi-faceted Intrusion Detection System (IDS) with capabilities for network traffic monitoring, anomaly detection, signature-based threat identification, file integrity monitoring, and basic email analysis. It is designed to be modular and extensible.

## Features

*   **Network Intrusion Detection (NIDS):**
    *   Real-time packet capture and analysis using Scapy.
    *   Flow-based traffic analysis (packet size, packet rate, byte rate).
    *   **Signature-Based Detection:** Identifies known malicious patterns (e.g., basic port scans, SYN floods).
    *   **Anomaly-Based Detection:** Uses `sklearn.ensemble.IsolationForest` to detect deviations from normal network behavior. Requires a training phase with normal traffic data.
*   **Feature Collection:** A dedicated script (`feature_collector.py`) to capture and save features from normal network traffic, which are then used to train the anomaly detector.
*   **Alerting System:** Logs detected threats and anomalies to `ids_alerts.log` and optionally to the console.
*   **File Integrity Monitor (FIM):**
    *   Calculates SHA256 hashes of files in a specified directory.
    *   Creates a baseline of file hashes (`file_baseline.json`).
    *   Detects new, modified, or deleted files by comparing current hashes against the baseline.
*   **Email Analysis (Basic):**
    *   `mailbox_monitor.py`: Connects to an IMAP server (e.g., Gmail via App Password), fetches unread emails.
    *   `email_analyzer.py`: Parses `.eml` files, extracts headers, attachments, and URLs. It performs basic checks for suspicious attachments (by extension) and URLs (known shorteners, suspicious keywords/extensions).
*   **Dashboard (Conceptual):** A `dashboard.py` using Streamlit is included, providing a basic structure for future UI development to display FIM and Mailbox monitor results.

## Project Structure

```
.
├── main.py                     # Main script to run the NIDS
├── packet_capture.py           # Handles packet sniffing
├── traffic_analyzer.py         # Analyzes packet data and extracts features
├── detection_engine.py         # Contains signature and anomaly detection logic
├── alert_system.py             # Manages alert generation and logging
├── feature_collector.py        # Script to collect data for training anomaly detection
├── file_integrity_monitor.py   # Script for file integrity checking
├── email_analyzer.py           # Logic for parsing and analyzing .eml files
├── mailbox_monitor.py          # Script to fetch and analyze emails from a mailbox
├── dashboard.py                # Streamlit dashboard for FIM and Email (WIP)
├── requirements.txt            # Python dependencies
├── ids_alerts.log              # Log file for NIDS alerts (created on first alert)
├── normal_traffic_features.npy # Stores data for anomaly detection training (created by feature_collector.py)
├── file_baseline.json          # Stores baseline for FIM (created by file_integrity_monitor.py)
├── .gitignore                  # Specifies intentionally untracked files
├── .env                        # For storing sensitive credentials like email app password (ensure it's in .gitignore)
└── README.md                   # This file
```

## Setup Instructions

1.  **Clone the Repository:**
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Create and Activate Virtual Environment:**
    It's highly recommended to use a virtual environment.
    ```bash
    python -m venv venv
    # On Windows
    .\venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Install Npcap (Windows Only):**
    For packet sniffing (`scapy`) to work correctly on Windows, you need to install Npcap.
    *   Download Npcap from [npcap.com](https://npcap.com/).
    *   During installation, ensure you check the box "Install Npcap in WinPcap API-compatible mode".

5.  **Administrator Privileges (for NIDS):**
    Running `main.py` or `feature_collector.py` (which perform packet capture) requires administrator/root privileges.

6.  **Configure Email Monitoring (Optional):**
    If you want to use `mailbox_monitor.py`:
    *   Create a `.env` file in the root directory.
    *   Add your email credentials. For Gmail, it's recommended to use an "App Password".
        ```env
        IMAP_SERVER=imap.gmail.com
        EMAIL_ACCOUNT=your_email@gmail.com
        APP_PASSWORD=your_gmail_app_password
        MAILBOX_TO_SCAN=INBOX 
        # Set MAILBOX_TO_SCAN to a specific folder or 'INBOX'
        ```
    *   Ensure `.env` is listed in your `.gitignore` file (it should be by default with the provided .gitignore).

## How to Run

Ensure your virtual environment is activated and you have installed Npcap if on Windows.

### 1. Network Intrusion Detection System (NIDS)

*   **a) Collect Training Data (First-time setup for Anomaly Detection):**
    Run this script with administrator/root privileges. It will capture a number of packets (default 500) from the specified interface to create `normal_traffic_features.npy`.
    ```bash
    # List available interfaces (optional, to find the correct one)
    python feature_collector.py --list_interfaces 
    # Collect features (replace 'Wi-Fi' with your active network interface)
    sudo python feature_collector.py --interface "Wi-Fi" 
    # Or on Windows (run terminal as Administrator):
    python feature_collector.py --interface "Wi-Fi" 
    ```

*   **b) Start the NIDS:**
    Run this script with administrator/root privileges.
    ```bash
    # Replace 'Wi-Fi' with your active network interface
    sudo python main.py --interface "Wi-Fi"
    # Or on Windows (run terminal as Administrator):
    python main.py --interface "Wi-Fi"
    ```
    The IDS will start monitoring traffic. Alerts will be logged to `ids_alerts.log` and printed to the console. Press `Ctrl+C` to stop.

### 2. File Integrity Monitor (FIM)

*   **a) Create a Baseline:**
    ```bash
    python file_integrity_monitor.py
    ```
    The script will prompt you to enter the full path of the directory you want to monitor and then ask if you want to `(c)reate` a baseline or `(k)check` integrity. Choose `c`. This will create `file_baseline.json`.

*   **b) Check Integrity:**
    Run the script again, provide the same directory, and choose `(k)check`. It will compare the current state of the directory against `file_baseline.json` and report any changes.
    ```bash
    python file_integrity_monitor.py
    ```

### 3. Email Mailbox Monitor

Ensure your `.env` file is configured as described in the Setup section.
```bash
python mailbox_monitor.py
```
This will fetch unread emails from the configured mailbox, analyze them using `email_analyzer.py`, print the analysis to the console, and mark them as read.

### 4. Streamlit Dashboard (Work in Progress)
To run the dashboard:
```bash
streamlit run dashboard.py
```
This will open the dashboard in your web browser. Currently, it has placeholders and basic integration for FIM and Mailbox scanning.

## Dependencies

All Python dependencies are listed in `requirements.txt`. Key libraries include:

*   `scapy`: For packet manipulation and capture.
*   `scikit-learn`: For the Isolation Forest anomaly detection model.
*   `numpy`: For numerical operations.
*   `python-dotenv`: For managing environment variables.
*   `beautifulsoup4`: For parsing HTML content from emails.
*   `streamlit`: For the web dashboard.

## Future Enhancements

*   More sophisticated signature rules.
*   Advanced feature engineering for anomaly detection.
*   Integration with external threat intelligence feeds.
*   Persistent storage for anomaly detection model training.
*   Full development of the Streamlit dashboard for comprehensive visualization and interaction.
*   More detailed email analysis (e.g., URL reputation checking, sandbox integration for attachments). 