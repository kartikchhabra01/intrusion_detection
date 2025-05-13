import streamlit as st
import os # For path joining and getenv
import file_integrity_monitor as fim # Import the refactored FIM script
import mailbox_monitor as mbm # Import the refactored mailbox monitor
import dotenv

dotenv.load_dotenv(override=True) # Ensure .env is loaded

def show_nids_page():
    st.header("Network Intrusion Detection System (NIDS)")
    st.write("NIDS monitoring and alerts will be displayed here.")
    # Placeholder for NIDS functionality

def show_fim_page():
    st.header("File Integrity Monitor (FIM)")

    # Use session state to remember the last used directory and baseline file
    if 'fim_directory' not in st.session_state:
        st.session_state.fim_directory = os.getcwd() # Default to current working directory
    if 'fim_baseline_file' not in st.session_state:
        # Default baseline file in the directory of dashboard.py
        st.session_state.fim_baseline_file = os.path.join(os.getcwd(), fim.BASELINE_FILE_DEFAULT)

    st.subheader("Configuration")
    directory_to_monitor = st.text_input(
        "Directory to Monitor", 
        value=st.session_state.fim_directory,
        key="fim_dir_input"
    )
    baseline_file_path_input = st.text_input(
        "Baseline File Path (e.g., /path/to/baseline.json)", 
        value=st.session_state.fim_baseline_file,
        key="fim_baseline_input"
    )

    # Update session state if inputs change
    st.session_state.fim_directory = directory_to_monitor
    st.session_state.fim_baseline_file = baseline_file_path_input

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Create/Update Baseline", key="create_baseline_btn"):
            if not directory_to_monitor:
                st.error("Please enter a directory to monitor.")
            elif not os.path.isdir(directory_to_monitor):
                st.error(f"Error: Directory '{directory_to_monitor}' does not exist or is not accessible.")
            elif not baseline_file_path_input:
                st.error("Please enter a path for the baseline file.")
            else:
                with st.spinner(f"Creating baseline for '{directory_to_monitor}'..."):
                    success, msg, baseline_data = fim.create_baseline(directory_to_monitor, baseline_file_path_input)
                if success:
                    st.success(msg)
                    if baseline_data:
                        st.write("Baseline Data Created:")
                        # Display a sample or summary if too large
                        if len(baseline_data) > 10:
                            st.json(dict(list(baseline_data.items())[:10]))
                            st.caption(f"... and {len(baseline_data) - 10} more entries.")
                        else:
                            st.json(baseline_data)
                else:
                    st.error(msg)
    
    with col2:
        if st.button("Check Integrity", key="check_integrity_btn"):
            if not directory_to_monitor:
                st.error("Please enter a directory to monitor.")
            elif not os.path.isdir(directory_to_monitor):
                st.error(f"Error: Directory '{directory_to_monitor}' does not exist or is not accessible.")
            elif not baseline_file_path_input:
                st.error("Please enter a path for the baseline file.")
            elif not os.path.exists(baseline_file_path_input):
                st.error(f"Error: Baseline file '{baseline_file_path_input}' not found. Please create it first.")
            else:
                with st.spinner(f"Checking integrity of '{directory_to_monitor}'..."):
                    results, summary_msg = fim.check_integrity(directory_to_monitor, baseline_file_path_input)
                
                st.info(summary_msg) # Display the overall summary message

                if results:
                    st.subheader("Integrity Check Details")
                    if results.get('modified'):
                        st.warning("Modified Files:")
                        for item in results['modified']:
                            st.write(f"- `{item['path']}` (Old: `{item['old_hash'][:10]}...`, New: `{item['new_hash'][:10]}...`)")
                    if results.get('new'):
                        st.success("New Files Found:") # Using st.success for new, but could be neutral
                        for item in results['new']:
                            st.write(f"- `{item['path']}` (Hash: `{item['hash'][:10]}...`)")
                    if results.get('deleted'):
                        st.error("Deleted Files:")
                        for item in results['deleted']:
                            st.write(f"- `{item['path']}` (Old Hash: `{item['old_hash'][:10]}...`)")
                    if results.get('errors'):
                        st.error("Unreadable Files During Check:")
                        for item_path in results['errors']:
                            st.write(f"- `{item_path}`")
                    
                    if not results.get('modified') and not results.get('new') and not results.get('deleted') and not results.get('errors'):
                        if "No changes detected" not in summary_msg: # Avoid double messaging if summary already clear
                             st.success("No changes detected based on the detailed check.")

def show_email_analysis_page():
    st.header("Email Analysis")

    st.subheader("IMAP Configuration")

    # Session state for IMAP settings
    if 'imap_server' not in st.session_state:
        st.session_state.imap_server = os.getenv('IMAP_SERVER', mbm.IMAP_SERVER_DEFAULT)
    if 'email_account' not in st.session_state:
        st.session_state.email_account = os.getenv('EMAIL_ACCOUNT', "")
    if 'app_password' not in st.session_state:
        st.session_state.app_password = os.getenv('APP_PASSWORD', "") # Load from .env if set
    if 'mailbox_to_scan' not in st.session_state:
        st.session_state.mailbox_to_scan = os.getenv('MAILBOX_TO_SCAN', mbm.MAILBOX_TO_SCAN_DEFAULT)
    if 'mark_as_read' not in st.session_state:
        st.session_state.mark_as_read = True

    imap_server = st.text_input("IMAP Server", value=st.session_state.imap_server)
    email_account = st.text_input("Email Account", value=st.session_state.email_account)
    app_password = st.text_input("App Password", type="password", value=st.session_state.app_password)
    mailbox_to_scan = st.text_input("Mailbox to Scan (e.g., INBOX)", value=st.session_state.mailbox_to_scan)
    mark_as_read_checkbox = st.checkbox("Mark emails as read after processing", value=st.session_state.mark_as_read)

    # Update session state from inputs
    st.session_state.imap_server = imap_server
    st.session_state.email_account = email_account
    st.session_state.app_password = app_password
    st.session_state.mailbox_to_scan = mailbox_to_scan
    st.session_state.mark_as_read = mark_as_read_checkbox

    if st.button("Fetch and Analyze Unread Emails", key="fetch_emails_btn"):
        if not imap_server or not email_account or not app_password or not mailbox_to_scan:
            st.error("Please fill in all IMAP configuration details.")
        else:
            with st.spinner(f"Fetching and analyzing emails from '{mailbox_to_scan}' for {email_account}..."):
                results, status_msg = mbm.fetch_and_analyze_unread_emails(
                    imap_server,
                    email_account,
                    app_password,
                    mailbox_to_scan,
                    mark_as_read=mark_as_read_checkbox
                )
            
            st.info(status_msg)

            if results:
                st.subheader(f"Found {len(results)} email(s) to display:")
                for i, res in enumerate(results):
                    email_subject = res.get('headers', {}).get('Subject', 'No Subject')
                    email_from = res.get('headers', {}).get('From', 'Unknown Sender')
                    assessment = res.get('overall_assessment', 'Assessment unavailable')
                    expander_title = f"Email ID: {res.get('email_id', 'N/A')} - From: {email_from} - Subject: {email_subject}"
                    
                    with st.expander(expander_title):
                        st.markdown(f"**Overall Assessment:** {assessment}")
                        if res.get('error'):
                            st.error(f"Error processing this email: {res['error']}")
                            continue
                        
                        st.markdown("**Headers:**")
                        st.json(res.get('headers', {}))
                        
                        st.markdown("**Attachments:**")
                        attachments = res.get('attachments', [])
                        if attachments:
                            for att in attachments:
                                att_status = "**SUSPICIOUS**" if att.get('is_suspicious') else "OK"
                                reason = f" - Reason: {att.get('suspicion_reason')}" if att.get('suspicion_reason') else ""
                                st.markdown(f"- {att.get('filename')} (Type: {att.get('content_type')}) - Status: {att_status}{reason}")
                        else:
                            st.write("No attachments found.")
                        
                        st.markdown("**URLs Found:**")
                        urls = res.get('urls', [])
                        if urls:
                            for url_item in urls:
                                url_status = "**SUSPICIOUS**" if url_item.get('is_suspicious') else "OK"
                                reason = f" - Reason: {url_item.get('reason')}" if url_item.get('reason') else ""
                                st.markdown(f"- `{url_item.get('url')}` - Status: {url_status}{reason}")
                        else:
                            st.write("No URLs found in the email body.")
            elif "No new unread emails found" not in status_msg and "Error" not in status_msg:
                 st.write("No analysis results to display from the latest fetch.")

def main():
    st.set_page_config(page_title="IDS Dashboard", layout="wide")
    st.title("Intrusion Detection System Dashboard")

    st.sidebar.title("Navigation")
    page_options = {
        "NIDS": show_nids_page,
        "File Integrity Monitor": show_fim_page,
        "Email Analysis": show_email_analysis_page
    }
    
    selection = st.sidebar.radio("Go to", list(page_options.keys()))

    # Basic password protection - NOT FOR PRODUCTION
    # For a real application, use a more secure method.
    password_placeholder = "ids_password" # Replace with a more secure way to get/store this if needed
    
    login_form = st.sidebar.empty() # Create a placeholder for the form
    
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        login_form.empty() # Remove login form after successful login
        page_options[selection]() # Display the selected page
    else:
        with login_form.form("login_form"):
            st.markdown("#### Login")
            entered_password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")

            if submitted:
                if entered_password == password_placeholder:
                    st.session_state.authenticated = True
                    st.sidebar.success("Login successful!")
                    # Force a re-run to clear the form and show the page
                    st.rerun() 
                else:
                    st.sidebar.error("Incorrect password.")
        
        st.info("Please log in using the sidebar to access the dashboard features.")


if __name__ == "__main__":
    main() 