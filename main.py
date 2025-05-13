from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from detection_engine import DetectionEngine
from alert_system import AlertSystem
from scapy.all import IP, TCP
import queue
import numpy as np
import os

TRAINING_DATA_FILE = "normal_traffic_features.npy"

class IntrusionDetectionSystem:
    def __init__(self, interface="Wi-Fi"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        self.interface = interface

        self._train_anomaly_detector_if_data_exists()

    def _train_anomaly_detector_if_data_exists(self):
        if os.path.exists(TRAINING_DATA_FILE):
            try:
                print(f"Found training data file: {TRAINING_DATA_FILE}. Attempting to train anomaly detector.")
                normal_traffic_data = np.load(TRAINING_DATA_FILE)
                if normal_traffic_data.ndim == 2 and normal_traffic_data.shape[1] == 3 and normal_traffic_data.shape[0] > 0:
                    self.detection_engine.train_anomaly_detector(normal_traffic_data)
                elif normal_traffic_data.shape[0] == 0:
                    print(f"[IDS Main] Training data file '{TRAINING_DATA_FILE}' is empty. Anomaly detection will be limited.")
                    print(f"Please run 'python feature_collector.py' to generate training data.")
                else:
                    print(f"[IDS Main] Training data in '{TRAINING_DATA_FILE}' has unexpected shape: {normal_traffic_data.shape}. Expected (n_samples, 3).")
                    print(f"Anomaly detection will be limited. Consider regenerating the training data.")
            except Exception as e:
                print(f"[IDS Main] Error loading or training with '{TRAINING_DATA_FILE}': {e}")
                print(f"Anomaly detection will be limited. Please check the file or run 'python feature_collector.py' to regenerate.")
        else:
            print(f"[IDS Main] Training data file '{TRAINING_DATA_FILE}' not found.")
            print("[IDS Main] Anomaly detection will be limited (or off if not previously trained).")
            print("Please run 'python feature_collector.py' to generate training data for the anomaly detector.")

    def start(self):
        print(f"🔍 Starting IDS on {self.interface}")
        if not self.detection_engine.anomaly_detector_fitted:
            print("[IDS Main] Note: Anomaly detector is not trained. IDS will rely on signature-based detection only.")
        
        self.packet_capture.start_capture(self.interface)

        try:
            while True:
                try:
                    packet = self.packet_capture.packet_queue.get(timeout=1)
                    features = self.traffic_analyzer.analyze_packet(packet)
                    if features:
                        threats = self.detection_engine.detect_threats(features)
                        for threat in threats:
                            packet_info = {}
                            if IP in packet:
                                packet_info['source_ip'] = packet[IP].src
                                packet_info['destination_ip'] = packet[IP].dst
                            # Add more packet details if needed, e.g., ports for TCP/UDP
                            if TCP in packet:
                                packet_info['source_port'] = packet[TCP].sport
                                packet_info['destination_port'] = packet[TCP].dport

                            self.alert_system.generate_alert(threat, packet_info)
                except queue.Empty:
                    continue
        except KeyboardInterrupt:
            print("\n🛑 Stopping IDS...")
        finally:
            self.packet_capture.stop()
            print("IDS stopped.")

if __name__ == "__main__":
    # Default interface, can be changed or made configurable
    # Ensure this interface name is correct for your system (e.g., "Ethernet 2", "Wi-Fi")
    active_interface = "Wi-Fi" 
    print(f"Attempting to start IDS on interface: {active_interface}")
    print("IMPORTANT: This script should be run with administrator/root privileges for packet capture.")
    ids = IntrusionDetectionSystem(interface=active_interface)
    ids.start()
