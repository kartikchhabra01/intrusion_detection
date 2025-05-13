from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination='auto', random_state=42)
        self.anomaly_detector_fitted = False
        self.signature_rules = self.load_signature_rules()

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda f: f.get('tcp_flags', None) == 2 and f.get('packet_rate', 0) > 100
            },
            'port_scan': {
                'condition': lambda f: f.get('packet_size', 0) < 100 and f.get('packet_rate', 0) > 50
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        if normal_traffic_data is not None and len(normal_traffic_data) > 0:
            self.anomaly_detector.fit(normal_traffic_data)
            self.anomaly_detector_fitted = True
            print("[DetectionEngine] Anomaly detector trained successfully.")
        else:
            print("[DetectionEngine] Warning: No data provided for anomaly detector training.")

    def detect_threats(self, features):
        threats = []

        for name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features):
                    threats.append({'type': 'signature', 'rule': name, 'confidence': 1.0})
            except KeyError as e:
                pass

        if self.anomaly_detector_fitted:
            try:
                feature_vector_data = [features['packet_size'], features['packet_rate'], features['byte_rate']]
                vector = np.array([feature_vector_data])
                score = self.anomaly_detector.score_samples(vector)[0]
                if score < -0.1:
                    threats.append({'type': 'anomaly', 'score': score, 'confidence': min(1.0, abs(score) * 2)})
            except KeyError as e:
                pass
        else:
            pass

        return threats
