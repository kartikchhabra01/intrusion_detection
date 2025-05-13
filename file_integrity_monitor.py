import os
import hashlib
import json
# import time # No longer needed by the core functions being refactored

BASELINE_FILE_DEFAULT = "file_baseline.json"
BUFFER_SIZE = 65536  # 64KB chunks for hashing large files

def calculate_sha256(file_path):
    """Calculates the SHA256 hash of a file. Returns hash string or None if error."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(BUFFER_SIZE)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except IOError as e:
        # This warning can be logged by the calling function if needed
        # print(f"Warning: Could not read file {file_path} for hashing: {e}")
        return None # Indicates an error to the caller

def create_baseline(directory_to_monitor, baseline_file_path):
    """
    Scans the specified directory, calculates hashes, and saves them to a baseline file.
    Returns: (bool: success, str: message, dict: baseline_data or None)
    """
    baseline = {}
    files_processed = 0
    errors_encountered = 0
    # print(f"Creating baseline for directory: {directory_to_monitor}") # UI will handle this

    for root, _, files in os.walk(directory_to_monitor):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_hash = calculate_sha256(file_path)
            if file_hash:
                relative_path = os.path.relpath(file_path, directory_to_monitor)
                baseline[relative_path] = file_hash
                files_processed += 1
                # print(f"  Hashed: {relative_path} -> {file_hash}") # UI will handle this
            else:
                errors_encountered += 1
                # Optionally log which file failed if needed for detailed report

    if not baseline and files_processed == 0 and errors_encountered > 0:
        return False, f"Error: No files could be hashed in {directory_to_monitor}. Check permissions or path.", None
    if not baseline and files_processed == 0 and errors_encountered == 0:
        return True, f"No files found in {directory_to_monitor} to create a baseline.", {}

    try:
        with open(baseline_file_path, 'w') as f:
            json.dump(baseline, f, indent=4)
        msg = f"Baseline successfully created with {files_processed} file(s) and saved to {baseline_file_path}."
        if errors_encountered > 0:
            msg += f" ({errors_encountered} file(s) could not be read)."
        return True, msg, baseline
    except IOError as e:
        return False, f"Error: Could not write baseline file to {baseline_file_path}: {e}", None

def load_baseline(baseline_file_path):
    """Loads the baseline from the specified file. Returns (baseline_dict, error_message_or_none)."""
    if not os.path.exists(baseline_file_path):
        return None, f"Error: Baseline file '{baseline_file_path}' not found."
    try:
        with open(baseline_file_path, 'r') as f:
            baseline = json.load(f)
        return baseline, None
    except (IOError, json.JSONDecodeError) as e:
        return None, f"Error: Could not read or parse baseline file '{baseline_file_path}': {e}"

def check_integrity(directory_to_monitor, baseline_file_path):
    """
    Checks the integrity of files against the baseline.
    Returns: (dict: results, str: message)
    Results dict contains: 'modified', 'new', 'deleted', 'errors', 'status'
    """
    results = {
        'modified': [],
        'new': [],
        'deleted': [],
        'errors': [], # Files that couldn't be read during check
        'status': 'Starting check...'
    }

    baseline, error_msg = load_baseline(baseline_file_path)
    if error_msg:
        results['status'] = error_msg
        return results, error_msg # Return immediately if baseline cannot be loaded

    current_files_on_disk = {}
    for root, _, files in os.walk(directory_to_monitor):
        for filename in files:
            file_path = os.path.join(root, filename)
            relative_path = os.path.relpath(file_path, directory_to_monitor)
            current_files_on_disk[relative_path] = file_path

    # Start with all baseline files as potentially deleted
    # Convert to list for easier modification if needed, or keep as set
    baseline_paths_set = set(baseline.keys())
    checked_paths_on_disk_set = set()

    found_changes_count = 0

    for rel_path, full_path_on_disk in current_files_on_disk.items():
        checked_paths_on_disk_set.add(rel_path)
        current_hash = calculate_sha256(full_path_on_disk)
        
        if not current_hash:
            results['errors'].append(rel_path)
            # print(f"Warning: Could not hash {rel_path} during check.") # UI can note this
            continue

        if rel_path in baseline:
            if baseline[rel_path] != current_hash:
                results['modified'].append({'path': rel_path, 'old_hash': baseline[rel_path], 'new_hash': current_hash})
                found_changes_count += 1
        else:
            results['new'].append({'path': rel_path, 'hash': current_hash})
            found_changes_count += 1

    # Files in baseline but not found on disk are deleted
    deleted_paths = list(baseline_paths_set - checked_paths_on_disk_set)
    for rel_path in deleted_paths:
        results['deleted'].append({'path': rel_path, 'old_hash': baseline.get(rel_path, 'N/A')})
    found_changes_count += len(deleted_paths)

    if found_changes_count == 0 and not results['errors']:
        final_message = "No changes detected. All monitored files are consistent with the baseline."
    elif found_changes_count == 0 and results['errors']:
        final_message = f"No direct changes detected, but {len(results['errors'])} file(s) could not be read during check."
    else:
        summary = []
        if results['modified']: summary.append(f"{len(results['modified'])} modified")
        if results['new']: summary.append(f"{len(results['new'])} new")
        if results['deleted']: summary.append(f"{len(results['deleted'])} deleted")
        if results['errors']: summary.append(f"{len(results['errors'])} unreadable")
        final_message = f"Integrity Check Complete. Changes found: {', '.join(summary)}."
    
    results['status'] = final_message
    return results, final_message

if __name__ == '__main__':
    # --- How to use (Command Line Interface) ---
    print("--- File Integrity Monitor (Command Line) ---")
    monitor_directory = input("Enter the full path of the directory to monitor: ")
    
    if not os.path.isdir(monitor_directory):
        print(f"Error: Directory '{monitor_directory}' does not exist.")
    else:
        print(f"Selected directory: {monitor_directory}")
        baseline_file = os.path.join(os.getcwd(), BASELINE_FILE_DEFAULT) # Save baseline in CWD
        print(f"The baseline file will be '{baseline_file}'.")
        
        action = input("Do you want to (c)reate a new baseline or (k)check integrity? (c/k): ").lower()

        if action == 'c':
            success, msg, _ = create_baseline(monitor_directory, baseline_file)
            print(msg)
        elif action == 'k':
            # Before checking, make sure baseline file exists in the expected location
            if not os.path.exists(baseline_file):
                print(f"Error: Baseline file '{baseline_file}' not found in the current directory.")
                print("Please create a baseline first or ensure it's in the correct location.")
            else:
                results, summary_msg = check_integrity(monitor_directory, baseline_file)
                print(f"\n--- Integrity Check Report ---")
                print(summary_msg)
                if results.get('modified'):
                    print("Modified Files:")
                    for item in results['modified']:
                        print(f"  - {item['path']} (Old: {item['old_hash'][:7]}..., New: {item['new_hash'][:7]}...)")
                if results.get('new'):
                    print("New Files:")
                    for item in results['new']:
                        print(f"  - {item['path']} (Hash: {item['hash'][:7]}...)")
                if results.get('deleted'):
                    print("Deleted Files:")
                    for item in results['deleted']:
                        print(f"  - {item['path']} (Old Hash: {item['old_hash'][:7]}...)")
                if results.get('errors'):
                    print("Unreadable Files During Check:")
                    for item_path in results['errors']:
                        print(f"  - {item_path}")
                print("--- End of Report ---")
        else:
            print("Invalid action. Please choose 'c' or 'k'.") 