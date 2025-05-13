import time
import numpy as np
from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
import queue

# Configuration
NUM_PACKETS_TO_COLLECT = 500  # Collect features from 500 packets
OUTPUT_FILE = "normal_traffic_features.npy"
# For a duration-based capture, you could use something like:
# CAPTURE_DURATION_SECONDS = 300 # 5 minutes

def collect_features():
    print(f"Starting feature collection for {NUM_PACKETS_TO_COLLECT} packets...")
    print("Please ensure your network activity is 'normal' during this period.")
    print(f"Features will be saved to {OUTPUT_FILE}")

    capturer = PacketCapture()
    analyzer = TrafficAnalyzer()
    
    # Use the actual interface name your main IDS uses, or make it configurable
    # For now, let's assume it might be Wi-Fi or Ethernet 2. 
    # Ideally, this should be consistent with main.py or configurable.
    # Trying common interface names; you might need to adjust this.
    # Scapy might pick the best one if iface is None, but explicit is better.
    interface_to_use = None # Let Scapy try to pick, or set one like "Wi-Fi"
    try:
        # Attempt to list interfaces to give user a hint if needed (optional)
        from scapy.all import get_if_list
        print(f"Available interfaces: {get_if_list()}")
        # You might want to prompt the user or read from a config here
        # For this script, let's default to None to let Scapy choose, 
        # or you can hardcode your typical interface if known, e.g., "Wi-Fi"
    except ImportError:
        print("Scapy not fully available to list interfaces, proceeding with default.")
    except Exception as e:
        print(f"Could not list interfaces: {e}, proceeding with default.")

    capturer.start_capture(interface=interface_to_use) 

    collected_features_list = []
    packets_processed = 0
    
    # start_time = time.time()
    print("Capturing packets...")

    try:
        while packets_processed < NUM_PACKETS_TO_COLLECT:
            # To use CAPTURE_DURATION_SECONDS:
            # if time.time() - start_time > CAPTURE_DURATION_SECONDS:
            #     print("Capture duration reached.")
            #     break
            try:
                packet = capturer.packet_queue.get(timeout=1) # 1-second timeout
                features = analyzer.analyze_packet(packet)
                if features:
                    # We need packet_size, packet_rate, byte_rate for the anomaly detector
                    try:
                        feature_vector = [
                            features['packet_size'], 
                            features['packet_rate'], 
                            features['byte_rate']
                        ]
                        collected_features_list.append(feature_vector)
                        packets_processed += 1
                        if packets_processed % 50 == 0:
                            print(f"Processed {packets_processed}/{NUM_PACKETS_TO_COLLECT} packets...")
                    except KeyError as e:
                        # print(f"Skipping packet due to missing feature: {e}")
                        pass # If essential features are missing, skip this packet

            except queue.Empty:
                # No packet in the last second, continue waiting
                # print(".", end="", flush=True) # Optional: to show it's alive
                continue
    except KeyboardInterrupt:
        print("\nFeature collection interrupted by user.")
    finally:
        print("Stopping packet capture...")
        capturer.stop()

    if collected_features_list:
        features_array = np.array(collected_features_list)
        np.save(OUTPUT_FILE, features_array)
        print(f"Successfully collected {len(features_array)} feature sets.")
        print(f"Normal traffic features saved to {OUTPUT_FILE}")
    else:
        print("No features were collected. The output file was not created.")

if __name__ == "__main__":
    print("IMPORTANT: This script should be run with administrator/root privileges for packet capture.")
    # Potentially add a check for admin rights here if possible for the OS
    collect_features() 