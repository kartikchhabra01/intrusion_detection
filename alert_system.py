import logging
import json
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS")
        self.logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        # Also print to console for immediate feedback during execution
        # console_handler = logging.StreamHandler() # REMOVE
        # console_handler.setFormatter(formatter) # REMOVE
        # self.logger.addHandler(console_handler) # REMOVE

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'confidence': threat['confidence'],
            'details': threat,
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip')
        }
        alert_json = json.dumps(alert)
        self.logger.warning(alert_json)
        # print(f"ALERT: {alert_json}") # Alternative direct print, logger approach is cleaner
