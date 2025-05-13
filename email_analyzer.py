import email
import email.parser
import email.policy
import argparse
import re
import os # Added for os.path.splitext
import html # Added for html.unescape
from bs4 import BeautifulSoup # For parsing HTML content to find links
from urllib.parse import urlparse # Added for URL parsing

# Basic regex for extracting URLs - can be improved
URL_REGEX = r"(?:http[s]?://|www\.)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"

# Define a set of suspicious extensions (lowercase)
SUSPICIOUS_EXTENSIONS = {
    # Executables
    '.exe', '.msi', '.bat', '.cmd', '.com', '.scr',
    # Scripts
    '.vbs', '.js', '.jse', '.ps1', '.py', '.jar', '.sh',
    # Office macros (older and newer)
    '.docm', '.xlsm', '.pptm',
    '.doc', '.xls', '.ppt', # Often restricted, but can still carry macros or exploits
    # Archives that can contain anything
    '.zip', '.rar', '.7z', # Often benign, but attackers use them to hide malware
    # Other potentially risky types
    '.iso', '.img', '.hta', '.chm', '.wsf'
}

# Define some extensions that are often part of legitimate double extensions but can be abused
# e.g. mydoc.pdf.exe
COMMON_DOC_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.jpg', '.png', '.gif'}

# --- URL Suspicion Definitions ---
SUSPICIOUS_URL_SHORTENERS = {
    'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', # t.co is Twitter's shortener, often abused
    'is.gd', 'buff.ly', 'adf.ly', 'shorte.st', 'cur.lv'
}

# Keywords often found in phishing URLs (not exhaustive, context matters)
SUSPICIOUS_URL_KEYWORDS = {
    'login', 'verify', 'account', 'update', 'secure', 'support', 'banking', 'ebayisapi'
}

# File extensions in URL paths that are suspicious
SUSPICIOUS_URL_EXTENSIONS = {'.exe', '.zip', '.rar', '.msi', '.js', '.vbs', '.bat', '.cmd', '.scr'}
# --- End URL Suspicion Definitions ---

def check_attachment_suspicion(filename):
    """Checks if an attachment filename is suspicious."""
    if not filename:
        return None, False # No filename to check

    name_lower = filename.lower()
    # Split the filename to get all parts for double extension check
    parts = name_lower.split('.')
    
    # Check 1: Direct suspicious extension (last part)
    if len(parts) > 1:
        extension = "." + parts[-1]
        if extension in SUSPICIOUS_EXTENSIONS:
            return f"Suspicious extension: {extension}", True

    # Check 2: Double extension (e.g., file.pdf.exe)
    # If there are 3 or more parts (name.ext1.ext2)
    # and ext1 is a common document type but ext2 is a suspicious one.
    if len(parts) >= 3:
        ext1 = "." + parts[-2]
        ext2 = "." + parts[-1]
        if ext1 in COMMON_DOC_EXTENSIONS and ext2 in SUSPICIOUS_EXTENSIONS:
            return f"Suspicious double extension: {ext1}{ext2}", True
    
    # Check for suspicious extensions that might be hidden without a common doc extension before them
    # e.g. mydocument.exe (where .exe is the only extension after the name)
    # This is covered by Check 1 if parts[-1] is the suspicious one.

    # Optional: Check if a known benign extension is followed by something unusual
    # For example, filename.jpg.xyz (this is less common but possible)
    # This case requires a more nuanced definition of "unusual"

    return None, False # Not deemed suspicious by current checks

def check_url_suspicion(url_string):
    """Checks if a URL string is suspicious based on several criteria."""
    if not url_string:
        return None, False

    try:
        parsed_url = urlparse(url_string)
        hostname = parsed_url.hostname
        path = parsed_url.path.lower()

        if not hostname: # Relative URLs or mailto links, etc.
            return None, False

        # 1. Check for known URL shorteners
        # Check root domain and subdomains (e.g. abc.bit.ly)
        for shortener_domain in SUSPICIOUS_URL_SHORTENERS:
            if hostname == shortener_domain or hostname.endswith('.' + shortener_domain):
                return f"Known URL shortener: {hostname}", True

        # 2. Check for IP address as hostname (common in direct malware links)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            return f"Direct IP address link: {hostname}", True
        
        # 3. Check for suspicious file extensions in the URL path
        for ext in SUSPICIOUS_URL_EXTENSIONS:
            if path.endswith(ext):
                return f"Suspicious file extension in URL path: {ext}", True

        # 4. Check for multiple subdomains (e.g., login.microsoft.com.someothersite.com)
        # This is a heuristic and might have false positives
        if hostname.count('.') >= 3: # e.g. sub1.sub2.domain.com (3 dots)
            # Further refine: if common keywords are in subdomains of a non-standard TLD
            # This needs more sophisticated TLD list management
            pass # For now, just the count is a weak indicator

        # 5. Check for suspicious keywords in the hostname or path (less reliable, use with caution)
        # for keyword in SUSPICIOUS_URL_KEYWORDS:
        #     if keyword in hostname.lower() or keyword in path:
        #         return f"Suspicious keyword '{keyword}' in URL", True # Too many false positives usually

    except Exception as e:
        # print(f"Error parsing URL '{url_string}': {e}") # Optional: for debugging
        return f"Could not parse URL", False # Treat unparseable URLs as non-suspicious for now

    return None, False # Not deemed suspicious by current checks

def analyze_email_file(file_path):
    """
    Analyzes a single .eml file and returns a dictionary of findings.
    """
    analysis_results = {
        'file_path': file_path,
        'error': None,
        'headers': {},
        'attachments': [],
        'urls': [],
        'overall_assessment': 'Could not be determined due to error.',
        'any_suspicious_attachment': False,
        'any_suspicious_url': False
    }

    try:
        with open(file_path, 'rb') as fp:
            msg = email.parser.BytesParser(policy=email.policy.default).parse(fp)
    except FileNotFoundError:
        analysis_results['error'] = f"File not found at '{file_path}'"
        return analysis_results
    except Exception as e:
        analysis_results['error'] = f"Error reading or parsing email file: {e}"
        return analysis_results

    analysis_results['headers'] = {
        'From': msg.get('From'),
        'To': msg.get('To'),
        'Subject': msg.get('Subject'),
        'Date': msg.get('Date')
        # Add more headers if needed by dashboard, e.g., 'Return-Path'
    }

    # Temporary lists for processing within this function before adding to results dict
    processed_attachments = []
    processed_urls = [] 
    any_suspicious_attachment_found = False
    any_suspicious_url_found = False

    unique_cleaned_urls_in_email = set() # To store cleaned URLs and avoid duplicates in the final list

    for part in msg.walk():
        content_disposition = part.get("Content-Disposition")
        content_type = part.get_content_type()
        filename = part.get_filename()

        if filename:
            suspicion_reason, is_suspicious = check_attachment_suspicion(filename)
            if is_suspicious:
                any_suspicious_attachment_found = True
            processed_attachments.append({
                'filename': filename,
                'content_type': content_type,
                'is_suspicious': is_suspicious,
                'suspicion_reason': suspicion_reason
            })
        
        if part.is_multipart():
            continue
        
        payload = part.get_payload(decode=True)
        charset = part.get_content_charset() or 'utf-8'
        body_content = ""
        try:
            body_content = payload.decode(charset, errors='replace')
        except (UnicodeDecodeError, AttributeError, LookupError):
            try:
                body_content = payload.decode('latin-1', errors='replace')
            except: # Final fallback
                body_content = ""
        
        if body_content:
            extracted_raw_urls_from_part = set()
            if "text/html" in content_type:
                soup = BeautifulSoup(body_content, 'html.parser')
                for a_tag in soup.find_all('a', href=True):
                    extracted_raw_urls_from_part.add(a_tag['href'])
            
            found_in_part_regex = re.findall(URL_REGEX, body_content)
            for url_regex in found_in_part_regex:
                extracted_raw_urls_from_part.add(url_regex)

            for raw_url in extracted_raw_urls_from_part:
                cleaned_url_text = html.unescape(raw_url)
                match = re.match(URL_REGEX, cleaned_url_text)
                if match:
                    cleaned_url_text = match.group(0)
                else:
                    continue
                
                cleaned_url_text = cleaned_url_text.strip()
                if not cleaned_url_text or cleaned_url_text in unique_cleaned_urls_in_email:
                    continue
                
                unique_cleaned_urls_in_email.add(cleaned_url_text)

                url_for_analysis = cleaned_url_text
                parsed_for_scheme = urlparse(url_for_analysis)
                if not parsed_for_scheme.scheme:
                    url_for_analysis = "http://" + url_for_analysis
                
                reason, is_suspicious = check_url_suspicion(url_for_analysis)
                if is_suspicious:
                    any_suspicious_url_found = True
                processed_urls.append({'url': cleaned_url_text, 'is_suspicious': is_suspicious, 'reason': reason})

    analysis_results['attachments'] = processed_attachments
    analysis_results['urls'] = sorted(processed_urls, key=lambda x: x['url']) # Sort for consistent output
    analysis_results['any_suspicious_attachment'] = any_suspicious_attachment_found
    analysis_results['any_suspicious_url'] = any_suspicious_url_found

    if not any_suspicious_attachment_found and not any_suspicious_url_found:
        analysis_results['overall_assessment'] = "This email appears to be okay based on current checks."
    else:
        details = []
        if any_suspicious_attachment_found: details.append("suspicious attachments")
        if any_suspicious_url_found: details.append("suspicious URLs")
        analysis_results['overall_assessment'] = f"This email contains potentially suspicious elements: {', '.join(details)}. Please review carefully."
    
    return analysis_results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze an .eml email file for suspicious content.")
    parser.add_argument("email_file", help="Path to the .eml file to analyze.")
    args = parser.parse_args()
    
    # print(f"\n--- Analyzing Email File (CLI Mode): {args.email_file} ---")
    results = analyze_email_file(args.email_file)
    
    if results['error']:
        print(f"Error: {results['error']}")
    else:
        print("\n[+] Basic Headers:")
        for key, value in results['headers'].items():
            print(f"  {key}: {value}")
        
        print("\n[+] Attachments Summary:")
        if results['attachments']:
            for att in results['attachments']:
                status = " (SUSPICIOUS)" if att['is_suspicious'] else ""
                reason_text = f" - Reason: {att['suspicion_reason']}" if att['suspicion_reason'] else ""
                print(f"  - {att['filename']} (Type: {att['content_type']}){status}{reason_text}")
        else:
            print("  No attachments found.")

        print("\n[+] URLs Found:")
        if results['urls']:
            for item in results['urls']:
                status = " (SUSPICIOUS)" if item['is_suspicious'] else ""
                reason_text = f" - Reason: {item['reason']}" if item['reason'] else ""
                print(f"  - {item['url']}{status}{reason_text}")
        else:
            print("  No URLs found in the email body.")

        print("\n[+] Overall Assessment:")
        print(f"  {results['overall_assessment']}")
    
    # print("\n--- Analysis Complete (CLI Mode) ---") 