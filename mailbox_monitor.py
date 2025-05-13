import imaplib
import email
# import time # No longer needed for the core fetching logic
import os
import tempfile
import dotenv
import json # For printing results in CLI mode
from email_analyzer import analyze_email_file

dotenv.load_dotenv(override=True)

# --- Configuration --- 
# Loaded from .env or can be passed as arguments to fetch_and_analyze_unread_emails
IMAP_SERVER_DEFAULT = 'imap.gmail.com'
MAILBOX_TO_SCAN_DEFAULT = 'INBOX'
# SUSPICIOUS_FOLDER_DEFAULT = 'All Mail' # Not used in this refactored version yet

def fetch_and_analyze_unread_emails(imap_server_host, email_address, app_password_val, mailbox_name, mark_as_read=True):
    """
    Connects to an IMAP server, fetches unread emails from a specified mailbox,
    analyzes them, and optionally marks them as read.

    Args:
        imap_server_host (str): The IMAP server hostname.
        email_address (str): The email account username.
        app_password_val (str): The app password for the email account.
        mailbox_name (str): The name of the mailbox to scan (e.g., 'INBOX').
        mark_as_read (bool): If True, marks processed emails as \Seen. Default True.

    Returns:
        tuple: (list_of_analysis_results, status_message_str)
               list_of_analysis_results is a list of dicts from analyze_email_file.
               status_message_str provides a summary or error.
    """
    processed_email_analyses = []
    
    if not all([imap_server_host, email_address, app_password_val, mailbox_name]):
        return [], "Error: IMAP server, email account, app password, or mailbox name is missing."

    try:
        mail = imaplib.IMAP4_SSL(imap_server_host)
        mail.login(email_address, app_password_val)
    except Exception as e:
        return [], f"Error connecting or logging in to {email_address}: {e}"

    try:
        status, _ = mail.select(mailbox_name, readonly=not mark_as_read)
        if status != 'OK':
            mail.logout()
            return [], f"Error selecting mailbox {mailbox_name}: {status}"
        
        status, email_ids_bytes = mail.search(None, 'UNSEEN')
        if status != 'OK':
            mail.logout()
            return [], f"Error searching for unread emails in {mailbox_name}: {status}"

        email_id_list = email_ids_bytes[0].split()

        if not email_id_list:
            mail.logout()
            return [], f"No new unread emails found in {mailbox_name}."

        summary_message = f"Found {len(email_id_list)} new unread email(s) in {mailbox_name}."

        for email_id_b in email_id_list:
            email_id_str = email_id_b.decode()
            # print(f"Processing email ID: {email_id_str}") # For CLI, if verbose
            
            status, msg_data = mail.fetch(email_id_b, '(RFC822)')
            if status != 'OK':
                processed_email_analyses.append({
                    'file_path': f'email_id_{email_id_str}',
                    'error': f"Error fetching email ID {email_id_str}: {status}",
                    'headers': {},
                    'attachments': [],
                    'urls': [],
                    'overall_assessment': 'Error fetching email.',
                    'any_suspicious_attachment': False,
                    'any_suspicious_url': False
                })
                continue

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    original_email_bytes = response_part[1]
                    tmp_eml_file = None # Define outside try block
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.eml', mode='wb') as tmp_eml:
                            tmp_eml.write(original_email_bytes)
                            temp_file_path = tmp_eml.name
                            tmp_eml_file = temp_file_path # Store for cleanup
                        
                        analysis_result = analyze_email_file(temp_file_path)
                        analysis_result['email_id'] = email_id_str # Add email_id to results
                        processed_email_analyses.append(analysis_result)
                        
                        if mark_as_read:
                            mail.store(email_id_b, '+FLAGS', '\\Seen')
                            # print(f"  Marked email ID {email_id_str} as read (Seen).")
                        
                    except Exception as analysis_e:
                         processed_email_analyses.append({
                            'file_path': f'email_id_{email_id_str}_analysis_error',
                            'error': f"Error during analysis of email ID {email_id_str}: {analysis_e}",
                            'headers': {},
                            'attachments': [],
                            'urls': [],
                            'overall_assessment': 'Error during local analysis.',
                            'any_suspicious_attachment': False,
                            'any_suspicious_url': False
                        })
                    finally:
                        if tmp_eml_file and os.path.exists(tmp_eml_file):
                            try:
                                os.remove(tmp_eml_file)
                            except OSError:
                                # print(f"Warning: Could not delete temporary file {tmp_eml_file}")
                                pass # Non-critical for function return
                    break # Processed this email_id
        
        mail.logout()
        return processed_email_analyses, summary_message

    except imaplib.IMAP4.abort as e:
        # Attempt to logout gracefully if possible
        try: mail.logout() 
        except: pass
        return processed_email_analyses, f"IMAP connection aborted: {e}. Partial results might be available."
    except Exception as e:
        try: mail.logout() 
        except: pass
        return processed_email_analyses, f"An unexpected error occurred: {e}. Partial results might be available."

if __name__ == "__main__":
    print("--- Mailbox Monitor (Single Run CLI) ---")
    
    # Load from .env - ensure these are set for CLI execution
    # For dashboard, these will likely be passed from Streamlit inputs/secrets
    env_imap_server = os.getenv('IMAP_SERVER', IMAP_SERVER_DEFAULT)
    env_email_account = os.getenv('EMAIL_ACCOUNT')
    env_app_password = os.getenv('APP_PASSWORD')
    env_mailbox = os.getenv('MAILBOX_TO_SCAN', MAILBOX_TO_SCAN_DEFAULT)

    if not env_email_account or not env_app_password:
        print("Error: EMAIL_ACCOUNT or APP_PASSWORD not found in .env file or environment variables.")
        print("Please ensure they are set to run the CLI test.")
    else:
        print(f"Attempting to connect to: {env_imap_server} for account: {env_email_account}")
        print(f"Scanning mailbox: {env_mailbox}")
        
        # For CLI, let's default to marking as read for now.
        # This could be a command-line argument later.
        results, status_msg = fetch_and_analyze_unread_emails(
            env_imap_server, 
            env_email_account, 
            env_app_password, 
            env_mailbox,
            mark_as_read=True 
        )
        
        print(f"\nStatus: {status_msg}")
        
        if results:
            print(f"\nProcessed {len(results)} email(s):")
            for i, res in enumerate(results):
                print(f"\n--- Email Analysis [{i+1}/{len(results)}] (ID: {res.get('email_id', 'N/A')}) ---")
                if res.get('error'):
                    print(f"  Error: {res['error']}")
                    continue
                
                print("  Headers:")
                for key, value in res.get('headers', {}).items():
                    print(f"    {key}: {value}")
                
                print("  Attachments:")
                if res.get('attachments'):
                    for att in res['attachments']:
                        status = " (SUSPICIOUS)" if att.get('is_suspicious') else ""
                        reason = f" - Reason: {att.get('suspicion_reason')}" if att.get('suspicion_reason') else ""
                        print(f"    - {att.get('filename')} (Type: {att.get('content_type')}){status}{reason}")
                else:
                    print("    No attachments found.")
                
                print("  URLs:")
                if res.get('urls'):
                    for url_item in res['urls']:
                        status = " (SUSPICIOUS)" if url_item.get('is_suspicious') else ""
                        reason = f" - Reason: {url_item.get('reason')}" if url_item.get('reason') else ""
                        print(f"    - {url_item.get('url')}{status}{reason}")
                else:
                    print("    No URLs found.")
                print(f"  Overall Assessment: {res.get('overall_assessment')}")
        else:
            if "No new unread emails found" not in status_msg and "Error" not in status_msg : # if not an error or no mail
                 print("No analysis results to display, but no errors reported during fetch.")

        print("\n--- CLI Run Complete ---") 