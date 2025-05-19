# lms_auditor/core/link_processor.py
import os
# import csv # Not used in this part
from urllib.parse import urlparse, quote
import re
import time
import base64
import requests
import traceback
from datetime import datetime # Keep for potential future use or if a utility function moves here
import json
from lms_auditor.config import app_settings # MODIFIED
# from .reference_handler import ReferenceManager # Not needed in this file currently
from bs4 import BeautifulSoup

VIDEO_PATTERNS_HOST = ['youtube.com', 'youtu.be', 'vimeo.com', 'player.vimeo.com', 'vidyard.com', 'panopto.com', 'echo360', 'microsoftstream.com', 'web.microsoftstream.com', 'teams.microsoft.com', 'zoom.us', 'kaltura.com']
IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico', '.heic', '.avif', '.tiff', '.tif']
AUDIO_EXTENSIONS = ['.mp3', '.wav', '.ogg', '.aac', '.m4a', '.flac', '.wma']
VIDEO_EXTENSIONS_FILES = ['.mp4', '.mov', '.avi', '.webm', '.mkv', '.flv', '.wmv', '.mpg', '.mpeg', '.m3u8', '.ts']

def _log_lp(message_content):
    try:
        q = app_settings.LOG_QUEUE
        if q and hasattr(q, 'put'):
            q.put(str(message_content) + "\n") # Ensure newline
            return
    except AttributeError:
        pass
    print(str(message_content), flush=True)

def categorize_link(absolute_url, current_page_final_url):
    parsed_abs_url = urlparse(absolute_url)
    path_lower = parsed_abs_url.path.lower()
    file_ext = os.path.splitext(path_lower)[1].lower()
    if not file_ext:
        query_ext_match = re.search(r'[?&][^=]+=.*?(\.\w{2,5})$', absolute_url, re.IGNORECASE)
        if query_ext_match:
            file_ext = query_ext_match.group(1).lower()

    result = {'url': absolute_url, 'file_ext': file_ext if file_ext in app_settings.DOWNLOADABLE_EXTENSIONS else None, 'type': 'unknown'} # MODIFIED app_settings

    if not parsed_abs_url.scheme or not parsed_abs_url.netloc or parsed_abs_url.scheme not in ['http', 'https']:
        result['type'] = 'skip'; result['reason'] = 'Non-http/s scheme or invalid URL structure'; return result

    is_lms = app_settings.LMS_SPECIFIC_DOMAIN == parsed_abs_url.netloc.lower() # MODIFIED app_settings
    is_uni = (parsed_abs_url.netloc.lower().endswith(f".{app_settings.UNIVERSITY_ROOT_DOMAIN.lower()}") or \
              parsed_abs_url.netloc.lower() == app_settings.UNIVERSITY_ROOT_DOMAIN.lower()) and not is_lms # MODIFIED app_settings (x2)
    domain_pfx = "lms_" if is_lms else ("uni_" if is_uni else "external_")

    if file_ext:
        if file_ext == '.pdf': result['type'] = f"{domain_pfx}file_pdf"
        elif file_ext in ['.doc', '.docx', '.odt', '.rtf', '.pages']: result['type'] = f"{domain_pfx}file_doc"
        elif file_ext in ['.ppt', '.pptx', '.odp', '.key']: result['type'] = f"{domain_pfx}file_ppt"
        elif file_ext in ['.xls', '.xlsx', '.ods', '.csv', '.numbers']: result['type'] = f"{domain_pfx}file_sheet"
        elif file_ext in IMAGE_EXTENSIONS: result['type'] = f"{domain_pfx}file_image"
        elif file_ext in AUDIO_EXTENSIONS: result['type'] = f"{domain_pfx}file_audio"
        elif file_ext in VIDEO_EXTENSIONS_FILES: result['type'] = f"{domain_pfx}file_video_direct"
        elif file_ext in ['.zip', '.rar', '.7z', '.tar', '.gz', '.iso']: result['type'] = f"{domain_pfx}file_archive"
        elif file_ext in app_settings.DOWNLOADABLE_EXTENSIONS : result['type'] = f"{domain_pfx}file_other" # MODIFIED app_settings
        if result['type'] != 'unknown':
            result['file_ext'] = file_ext
            return result

    plugin_match = None
    if is_lms:
        plugin_match = re.search(r"/pluginfile.php/(?:[^/]+/)*[^/?#]+\.(\w+)(?:[?#]|$)", absolute_url, re.IGNORECASE)
        if not plugin_match:
             plugin_match = re.search(r"/(?:forcedownload|content|file)\.php(?:.*?file=|.*?/)(?:[^/]+/)*[^/?#]+\.(\w+)(?:[?#]|$)", absolute_url, re.IGNORECASE)
        if not plugin_match:
             plugin_match = re.search(r"/[^/?#]+\.php(?:.*?/|.*?id=)(?:[^/]+/)*[^/?#]+\.(\w+)(?:[?#]|$)", absolute_url, re.IGNORECASE)

    if plugin_match:
        plugin_ext_guess = "." + plugin_match.group(1).lower()
        if plugin_ext_guess in app_settings.DOWNLOADABLE_EXTENSIONS: # MODIFIED app_settings
            result['file_ext'] = plugin_ext_guess
            if plugin_ext_guess == '.pdf': result['type'] = "lms_file_pdf"
            elif plugin_ext_guess in ['.doc', '.docx']: result['type'] = "lms_file_doc"
            elif plugin_ext_guess in ['.ppt', '.pptx']: result['type'] = "lms_file_ppt"
            elif plugin_ext_guess in ['.xls', '.xlsx', '.csv']: result['type'] = "lms_file_sheet"
            elif plugin_ext_guess in IMAGE_EXTENSIONS: result['type'] = "lms_file_image"
            elif plugin_ext_guess in AUDIO_EXTENSIONS: result['type'] = "lms_file_audio"
            elif plugin_ext_guess in VIDEO_EXTENSIONS_FILES: result['type'] = "lms_file_video_direct"
            elif plugin_ext_guess in ['.zip', '.rar', '.7z']: result['type'] = "lms_file_archive"
            else: result['type'] = "lms_file_plugin"
            return result

    if is_lms and any(patt in parsed_abs_url.path for patt in app_settings.INTERNAL_COURSE_PAGE_PATTERNS): # MODIFIED app_settings
        # DEBUG comments removed for brevity
        abs_url_base = absolute_url.split('#')[0].split('?')[0]
        current_page_base = current_page_final_url.split('#')[0].split('?')[0]
        abs_url_query = urlparse(absolute_url).query
        current_page_query = urlparse(current_page_final_url).query

        if abs_url_base != current_page_base or abs_url_query != current_page_query :
             result['type'] = 'lms_course_page'
        else:
             result['type'] = 'skip'
             result['reason'] = 'Self-referential (same base URL and query)'
        return result

    if is_lms: result['type'] = 'lms_other_page'; return result
    if is_uni: result['type'] = 'uni_other_page'; return result

    for vp_host in VIDEO_PATTERNS_HOST:
        if vp_host in parsed_abs_url.netloc.lower(): result['type'] = 'external_video_platform'; return result

    if any(viewer_domain in parsed_abs_url.netloc.lower() for viewer_domain in ['docs.google.com', 'onedrive.live.com', 'view.officeapps.live.com']):
        if 'url=' in parsed_abs_url.query.lower() or 'src=' in parsed_abs_url.query.lower():
            embedded_url_match = re.search(r'(?:url|src)=[^&]*?(\.\w{2,5})(?:&|$)', parsed_abs_url.query, re.IGNORECASE)
            if embedded_url_match:
                embedded_ext = embedded_url_match.group(1).lower()
                if embedded_ext == '.pdf': result['type'] = 'external_file_pdf_viewer'; result['file_ext'] = '.pdf'; return result
                if embedded_ext in ['.doc', '.docx']: result['type'] = 'external_file_doc_viewer'; result['file_ext'] = embedded_ext; return result
                if embedded_ext in ['.ppt', '.pptx']: result['type'] = 'external_file_ppt_viewer'; result['file_ext'] = embedded_ext; return result
            result['type'] = 'external_document_viewer'; return result

    result['type'] = 'external_other'; return result


def get_url_reputation_virustotal(url_to_check):
    # Define the default structure with INTEGERS for counts
    default_return_structure = {
        "status": "Not Scanned",
        "score_display": "N/A", # For display if needed, like "X/Y"
        "positives": 0,         # INTEGER
        "suspicious": 0,        # INTEGER
        "total_scans": 0,       # INTEGER
        "details_link": "#",
        "last_analysis_date": None # Or "N/A" if you prefer string for display
    }

    if not app_settings.ENABLE_VIRUSTOTAL_CHECKS:
        # Create a copy to avoid modifying the original default_return_structure
        result = default_return_structure.copy()
        result["status"] = "SKIPPED (VT Disabled)"
        return result

    if not app_settings.VIRUSTOTAL_API_KEY or "YOUR_ACTUAL_VIRUSTOTAL_API_KEY_HERE" in app_settings.VIRUSTOTAL_API_KEY:
        result = default_return_structure.copy()
        result["status"] = "SKIPPED (No API Key)"
        return result

    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": app_settings.VIRUSTOTAL_API_KEY, "Accept": "application/json", "User-Agent": app_settings.USER_AGENT_FOR_REQUESTS}
    
    # Use a log function if available, otherwise print
    log_func = getattr(app_settings, '_log_message', print) # Assuming you might add _log_message to app_settings or pass it
    log_func(f"  VT Check: {url_to_check[:70]}... ")

    # The public API limit is typically 4 requests per minute.
    # 16 seconds is slightly more than 15 seconds (60s/4).
    # Consider making this configurable or having a more sophisticated rate limiter if you make many calls.
    time.sleep(getattr(app_settings, 'VIRUSTOTAL_REQUEST_DELAY_SECONDS', 16))

    try:
        resp = requests.get(vt_url, headers=headers, timeout=30)
        
        # Handle 404: URL not found in VirusTotal
        if resp.status_code == 404:
            log_func("Not found in VT.\n")
            result = default_return_structure.copy()
            result["status"] = "Not found in VT"
            result["details_link"] = f"https://www.virustotal.com/gui/url/{url_id}/detection"
            # positives, suspicious, total_scans remain 0 as per default
            return result
            
        resp.raise_for_status() # Raise HTTPError for bad responses (4XX, 5XX)
        data = resp.json()

        if 'data' in data and 'attributes' in data['data']:
            attrs = data['data']['attributes']
            stats = attrs.get('last_analysis_stats', {})
            
            # Ensure these are integers
            malicious_count = int(stats.get('malicious', 0))
            suspicious_count = int(stats.get('suspicious', 0))
            
            # Calculate total_scans by summing relevant integer stats
            # VT API v3 'last_analysis_stats' keys: harmless, malicious, suspicious, timeout, undetected
            relevant_categories = ["harmless", "malicious", "suspicious", "timeout", "undetected"]
            total_valid_scans = sum(int(stats.get(cat, 0)) for cat in relevant_categories if isinstance(stats.get(cat), int))

            status_str = "Unknown"
            if malicious_count > 0:
                status_str = "Malicious"
            elif suspicious_count > 0:
                status_str = "Suspicious"
            elif total_valid_scans > 0: # Only say "Likely Safe" if there were actual scans
                status_str = "Likely Safe" # Or "Clean", "Harmless" depending on your preference
            else: # No malicious, no suspicious, and no other scan results (total_valid_scans is 0)
                status_str = "No Community Score / Not Scanned Yet"

            last_analysis_ts = attrs.get('last_analysis_date')
            last_analysis_str = None
            if last_analysis_ts:
                try:
                    last_analysis_str = datetime.utcfromtimestamp(last_analysis_ts).strftime('%Y-%m-%d %H:%M UTC')
                except (ValueError, TypeError):
                    last_analysis_str = "Invalid Date"


            summary = {
                "status": status_str,
                "score_display": f"{malicious_count}/{total_valid_scans}" if total_valid_scans > 0 else "N/A", # For display
                "positives": malicious_count,   # INTEGER
                "suspicious": suspicious_count, # INTEGER
                "total_scans": total_valid_scans, # INTEGER
                "details_link": f"https://www.virustotal.com/gui/url/{url_id}/detection",
                "last_analysis_date": last_analysis_str
            }
            log_func(f"Status: {summary['status']} (P:{malicious_count}, S:{suspicious_count}, Total Scans: {total_valid_scans})\n")
            return summary
        else:
            log_func("VT Format Error.\n")
            result = default_return_structure.copy()
            result["status"] = "VT Format Error"
            result["details"] = "Unexpected JSON structure" # Add a details key if you want
            return result
            
    except requests.exceptions.HTTPError as h_err:
        sc = h_err.response.status_code if h_err.response is not None else 'N/A'
        details_msg = str(h_err)
        try:
            err_data = h_err.response.json()
            details_msg = err_data.get('error',{}).get('message', details_msg)
        except: pass # Ignore if response is not JSON or error structure is different
        
        if sc == 401: details_msg = "API Key Invalid or Permissions Issue"
        elif sc == 429: details_msg = "VT Rate Limit Exceeded"
        elif sc == 400: details_msg = "Bad Request (e.g. invalid URL format for VT)"
        
        log_func(f" HTTP Error ({sc}): {details_msg}\n")
        result = default_return_structure.copy()
        result["status"] = f"VT HTTP Error ({sc})"
        result["details"] = details_msg
        return result
        
    except requests.exceptions.RequestException as r_err: # More general network errors
        log_func(f" Request Error: {r_err}\n")
        result = default_return_structure.copy()
        result["status"] = "VT Request Error"
        result["details"] = str(r_err)
        return result
        
    except Exception as e: # Catch any other unexpected errors
        log_func(f" Unexpected VT Error: {e}\n")
        import traceback
        traceback.print_exc() # Good for debugging
        result = default_return_structure.copy()
        result["status"] = "VT Unexpected Error"
        result["details"] = str(e)
        return result

def get_url_reputation_google_safe_browsing(url_to_check):
    default_gsb_return = {
        "status": "Not Scanned (GSB)", "positives": 0, "total_scans": 1, # GSB is one "engine"
        "details": "GSB check not performed or no threat found.", "source": "Google Safe Browsing",
        "details_link": f"https://transparencyreport.google.com/safe-browsing/search?url={quote(url_to_check, safe='')}" # General link
    }
    if not app_settings.ENABLE_GOOGLE_SAFE_BROWSING_CHECKS:
        default_gsb_return["status"] = "SKIPPED (GSB Disabled)"
        return default_gsb_return
    if not app_settings.GOOGLE_SAFE_BROWSING_API_KEY or \
       "YOUR_GOOGLE_SAFE_BROWSING_API_KEY_HERE" in app_settings.GOOGLE_SAFE_BROWSING_API_KEY:
        default_gsb_return["status"] = "SKIPPED (No GSB API Key)"
        return default_gsb_return

    _log_lp(f"  GSB Check: {url_to_check[:70]}...")
    try:
        threat_types_to_check = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
        
        params = {
            'key': app_settings.GOOGLE_SAFE_BROWSING_API_KEY,
            'uri': url_to_check,
            'threatTypes': threat_types_to_check 
        }
        
        time.sleep(getattr(app_settings, 'GSB_REQUEST_DELAY_SECONDS', 0.25)) # Short delay for GSB

        response = requests.get(app_settings.GOOGLE_SAFE_BROWSING_API_URL, params=params, timeout=20) # Increased timeout slightly

        _log_lp(f"  GSB Request URL: {response.url}") # Log the exact URL requests made

        if response.status_code == 200:
            data = response.json()
            # An empty JSON object {} means no threats were found for the specified types.
            if data and data.get("threat"): 
                threat_info = data["threat"]
                threat_types_found = ", ".join(threat_info.get("threatTypes", ["Unknown"]))
                _log_lp(f"  GSB WARNING for {url_to_check[:70]}: {threat_types_found}")
                return {
                    "status": f"Flagged by GSB ({threat_types_found})",
                    "positives": 1, 
                    "total_scans": 1,
                    "details": f"Threat types: {threat_types_found}. Cache until: {threat_info.get('expireTime', 'N/A')}",
                    "source": "Google Safe Browsing",
                    "details_link": f"https://transparencyreport.google.com/safe-browsing/search?url={quote(url_to_check, safe='')}"
                }
            else: 
                _log_lp(f"  GSB OK for {url_to_check[:70]}")
                default_gsb_return["status"] = "Clean (GSB)"
                default_gsb_return["details"] = "No threats found by Google Safe Browsing for specified threat types."
                return default_gsb_return
        else: 
            error_details = f"HTTP Error {response.status_code}"
            try:
                error_data = response.json() # Try to get more specific error from Google
                error_details += f" - {error_data.get('error', {}).get('message', response.text)}"
            except json.JSONDecodeError: # If response isn't JSON
                error_details += f" - {response.text}"
            _log_lp(f"  GSB Error for {url_to_check[:70]}: {error_details}")
            return {"status": "GSB API Error", "details": error_details, "source": "Google Safe Browsing", "details_link": default_gsb_return["details_link"]}

    except requests.exceptions.Timeout:
        _log_lp(f"  GSB Timeout for {url_to_check[:70]}")
        return {"status": "GSB Request Timeout", "details": "The request to Google Safe Browsing API timed out.", "source": "Google Safe Browsing", "details_link": default_gsb_return["details_link"]}
    except requests.exceptions.RequestException as e:
        _log_lp(f"  GSB Request Exception for {url_to_check[:70]}: {e}")
        return {"status": "GSB Request Exception", "details": str(e), "source": "Google Safe Browsing", "details_link": default_gsb_return["details_link"]}
    except Exception as e_gen:
        _log_lp(f"  GSB Unexpected Error for {url_to_check[:70]}: {e_gen}\n{traceback.format_exc()}")
        return {"status": "GSB Unexpected Error", "details": str(e_gen), "source": "Google Safe Browsing", "details_link": default_gsb_return["details_link"]}

def get_url_reputation_metadefender(url_to_check):
    default_md_return = {
        "status": "Not Scanned (MD)", "positives": 0, "total_scans": 0,
        "details": "Metadefender check not performed.", "source": "Metadefender Cloud",
        "details_link": f"https://metadefender.opswat.com/results/url/?url={quote(url_to_check, safe='')}"
    }
    if not app_settings.ENABLE_METADEFENDER_CHECKS:
        default_md_return["status"] = "SKIPPED (MD Disabled)"
        return default_md_return
    if not app_settings.METADEFENDER_API_KEY or \
       "YOUR_METADEFENDER_API_KEY_HERE" in app_settings.METADEFENDER_API_KEY:
        default_md_return["status"] = "SKIPPED (No MD API Key)"
        return default_md_return

    _log_lp(f"  Metadefender Check: {url_to_check[:70]}...")
    headers = {
        "apikey": app_settings.METADEFENDER_API_KEY,
        "Content-Type": "application/json",
        "User-Agent": getattr(app_settings, 'USER_AGENT_FOR_REQUESTS', 'LMSAuditor/1.0') # Use a default UA
    }
    
    time.sleep(getattr(app_settings, 'METADEFENDER_REQUEST_DELAY_SECONDS', 2)) 

    try:
        # Step 1: Submit URL for analysis/lookup
        payload = {"url": [url_to_check]} # Sending as an array based on previous error
        _log_lp(f"  Metadefender: Submitting URL {url_to_check[:70]} to {app_settings.METADEFENDER_URL_SCAN_API_URL} for analysis with payload: {json.dumps(payload)}")
        
        response_submit = requests.post(app_settings.METADEFENDER_URL_SCAN_API_URL, headers=headers, json=payload, timeout=30)
        
        _log_lp(f"  Metadefender Submit Status: {response_submit.status_code}")
        raw_submit_response_text = response_submit.text
        if raw_submit_response_text:
             _log_lp(f"  Metadefender Submit Response (raw): {raw_submit_response_text[:500]}...")

        # Handle specific HTTP error codes from submission
        if response_submit.status_code == 400:
            error_detail_400 = "Bad Request"
            try: error_detail_400 = response_submit.json().get("error",{}).get("messages",["Bad Request"])[0]
            except: pass
            _log_lp(f"  Metadefender Error: 400 Bad Request. Detail: {error_detail_400}")
            return {"status": "MD API Bad Request", "details": error_detail_400, "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}
        if response_submit.status_code == 401:
             _log_lp(f"  Metadefender Error: 401 Unauthorized. Check API Key.")
             return {"status": "MD API Key Invalid", "details": "401 Unauthorized", "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}
        if response_submit.status_code == 403:
             _log_lp(f"  Metadefender Error: 403 Forbidden. Check API limits/quota. Response: {raw_submit_response_text}")
             return {"status": "MD API Forbidden/Limit", "details": f"403 Forbidden - {raw_submit_response_text[:100]}", "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}
        if response_submit.status_code == 429:
             _log_lp(f"  Metadefender Error: 429 Too Many Requests. Rate limit likely exceeded.")
             return {"status": "MD API Rate Limit", "details": "429 Too Many Requests", "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}

        response_submit.raise_for_status() # For other errors like 5xx
        
        submit_data = response_submit.json()
        data_id = submit_data.get("data_id")

        # Handle immediate lookup result if data_id is not present but 'data' array is
        if not data_id and submit_data.get("data") and isinstance(submit_data["data"], list) and len(submit_data["data"]) > 0:
            _log_lp(f"  Metadefender: No data_id, attempting to parse direct 'data' array from submission response.")
            direct_lookup_info = submit_data["data"][0] # Assume first entry is relevant
            
            # This data_id might be present inside the "data" array for direct results
            # If available, it can be used for the details_link
            report_data_id = direct_lookup_info.get("data_id", None) 
            details_link_for_direct = f"https://metadefender.opswat.com/results/url/{report_data_id}/overview" if report_data_id else default_md_return["details_link"]

            # Try to parse "scan_results" (if scan completed quickly) or "lookup_results"
            current_scan_results = direct_lookup_info.get("scan_results")
            lookup_results = direct_lookup_info.get("lookup_results")

            overall_result_str = "Processing/Unknown" # Default for direct if not clear
            positives_count = 0
            total_engines_lookup = 0 # For lookup_results.sources
            total_engines_scan = 0 # For scan_details
            details_array = []

            if current_scan_results and current_scan_results.get("scan_all_result_a") is not None:
                overall_result_str = current_scan_results.get("scan_all_result_a", "Unknown Scan Result")
                scan_details_engines = direct_lookup_info.get("scan_details", {})
                if scan_details_engines:
                    total_engines_scan = len(scan_details_engines)
                    for engine_name, engine_data in scan_details_engines.items():
                        if isinstance(engine_data, dict) and engine_data.get("threat_found", ""):
                            positives_count += 1
                            details_array.append(f"{engine_name}: {engine_data.get('threat_found')}")
            elif lookup_results: # Fallback to lookup_results
                positives_count = lookup_results.get("detected_by", 0)
                if positives_count > 0:
                    overall_result_str = "Potentially Risky (Lookup)"
                else:
                    overall_result_str = "No Detections (Lookup)"
                
                sources_list = lookup_results.get("sources", [])
                if sources_list:
                    total_engines_lookup = len(sources_list)
                    for src in sources_list:
                        if src.get("assessment") and src.get("assessment").lower() not in ["trustworthy", "clean", "no risk found"]:
                             details_array.append(f"{src.get('provider')}: {src.get('assessment')}")
            
            final_total_scans = total_engines_scan if total_engines_scan > 0 else (total_engines_lookup if total_engines_lookup > 0 else 1)

            md_status_display = f"{overall_result_str} (MD Direct)"
            if positives_count > 0:
                 md_status_display = f"{overall_result_str} (MD Direct, {positives_count}/{final_total_scans} reports)"

            _log_lp(f"  Metadefender Direct Lookup for {url_to_check[:70]}: {md_status_display}")
            return {
                "status": md_status_display,
                "positives": positives_count,
                "total_scans": final_total_scans,
                "details": "; ".join(details_array) or overall_result_str,
                "source": "Metadefender Cloud (Direct)",
                "details_link": details_link_for_direct
            }

        # If we have a data_id, proceed to polling
        if not data_id:
            _log_lp(f"  Metadefender Error: Still no data_id after checking direct data. Response: {submit_data}")
            return {"status": "MD Submission Error", "details": f"No data_id. Resp: {str(submit_data)[:100]}", "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}

        _log_lp(f"  Metadefender: URL submitted for polling. Data ID: {data_id}. Polling for results...")
        poll_url = f"{app_settings.METADEFENDER_URL_INFO_API_URL}{data_id}"
        max_poll_attempts = getattr(app_settings, 'METADEFENDER_POLL_ATTEMPTS', 12)
        poll_interval = getattr(app_settings, 'METADEFENDER_POLL_INTERVAL_SECONDS', 10)
        
        for attempt in range(max_poll_attempts):
            time.sleep(poll_interval)
            _log_lp(f"  Metadefender: Polling attempt {attempt + 1}/{max_poll_attempts} for Data ID {data_id} at {poll_url}...")
            response_poll = requests.get(poll_url, headers=headers, timeout=30)
            _log_lp(f"  Metadefender Poll Status: {response_poll.status_code}")
            
            if response_poll.status_code == 200:
                poll_data = response_poll.json()
                current_scan_results = poll_data.get("scan_results")
                if not current_scan_results and poll_data.get("url_info", {}).get("scan_results"):
                    current_scan_results = poll_data.get("url_info", {}).get("scan_results")

                if current_scan_results:
                    progress = current_scan_results.get("progress_percentage", -1)
                    overall_result_str = current_scan_results.get("scan_all_result_a", None)
                    
                    if overall_result_str is not None and progress == 100 :
                        _log_lp(f"  Metadefender: Scan complete for {data_id}. Overall result: {overall_result_str}")
                        positives_count = 0; total_engines = 0; details_array = []
                        scan_details_engines = poll_data.get("scan_details", {})
                        if not scan_details_engines and poll_data.get("file_info", {}).get("scan_details"):
                            scan_details_engines = poll_data.get("file_info", {}).get("scan_details")
                        if scan_details_engines:
                            total_engines = len(scan_details_engines)
                            for engine_name, engine_data in scan_details_engines.items():
                                if isinstance(engine_data, dict) and engine_data.get("threat_found", ""):
                                    positives_count += 1
                                    details_array.append(f"{engine_name}: {engine_data.get('threat_found')}")
                        
                        md_status_display = f"{overall_result_str} (MD Poll)"
                        if positives_count > 0:
                             md_status_display = f"{overall_result_str} (MD Poll, {positives_count}/{total_engines or 'N/A'} engines)"
                        
                        return {
                            "status": md_status_display, "positives": positives_count,
                            "total_scans": total_engines if total_engines > 0 else 1,
                            "details": "; ".join(details_array) or overall_result_str,
                            "source": "Metadefender Cloud (Poll)",
                            "details_link": f"https://metadefender.opswat.com/results/url/{data_id}/overview"
                        }
                    else:
                        _log_lp(f"  Metadefender: Scan for {data_id} progress: {progress}%. Result: {overall_result_str}. Continuing poll...")
                else:
                     _log_lp(f"  Metadefender: Scan results key not found in poll data for {data_id}. Continuing poll...")
            elif response_poll.status_code == 404:
                 _log_lp(f"  Metadefender: Scan {data_id} still processing (poll returned 404)...")
            else:
                _log_lp(f"  Metadefender: Polling error {response_poll.status_code} for {data_id}. Response: {response_poll.text[:100]}")
        
        _log_lp(f"  Metadefender: Max polling attempts reached for {data_id}.")
        return {"status": "MD Scan Polling Timeout", "details": f"Max polling for data_id {data_id}", "source": "Metadefender Cloud (Poll)", "details_link": f"https://metadefender.opswat.com/results/url/{data_id}/overview"}

    except requests.exceptions.HTTPError as h_err:
        _log_lp(f"  Metadefender HTTP Error (overall): {h_err}")
        details = str(h_err); response_text_snippet = ""
        if h_err.response is not None:
            details = f"HTTP Error {h_err.response.status_code}"
            response_text_snippet = h_err.response.text[:100]
        return {"status": "MD HTTP Error", "details": f"{details} - {response_text_snippet}", "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}
    except requests.exceptions.RequestException as r_err:
        _log_lp(f"  Metadefender Request Exception: {r_err}")
        return {"status": "MD Request Exception", "details": str(r_err), "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}
    except json.JSONDecodeError as j_err:
        response_text_for_json_error = raw_submit_response_text if 'raw_submit_response_text' in locals() else "Response text unavailable"
        _log_lp(f"  Metadefender JSON Decode Error: {j_err}. Response was: {response_text_for_json_error[:200]}")
        return {"status": "MD JSON Error", "details": f"{j_err} on response: {response_text_for_json_error[:100]}", "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}
    except Exception as e_gen_md:
        _log_lp(f"  Metadefender Unexpected Error: {e_gen_md}\n{traceback.format_exc()}")
        return {"status": "MD Unexpected Error", "details": str(e_gen_md), "source": "Metadefender Cloud", "details_link": default_md_return["details_link"]}
    
def get_comprehensive_url_reputation(url_to_check):
    # ... (existing logic calling VT, GSB, MD and collecting results) ...
    _log_lp(f"COMPREHENSIVE_SCAN: Starting checks for URL: {url_to_check[:70]}...")
    final_results = []

    # 1. VirusTotal
    if app_settings.ENABLE_VIRUSTOTAL_CHECKS and app_settings.VIRUSTOTAL_API_KEY and "YOUR_ACTUAL" not in app_settings.VIRUSTOTAL_API_KEY:
        vt_result = get_url_reputation_virustotal(url_to_check)
        final_results.append(vt_result)
        # ... (optional early exit logic) ...
    else:
        _log_lp("COMPREHENSIVE_SCAN: VirusTotal checks skipped or API key missing.")

    # 2. Google Safe Browsing
    if app_settings.ENABLE_GOOGLE_SAFE_BROWSING_CHECKS and app_settings.GOOGLE_SAFE_BROWSING_API_KEY and "YOUR_GOOGLE" not in app_settings.GOOGLE_SAFE_BROWSING_API_KEY:
        gsb_result = get_url_reputation_google_safe_browsing(url_to_check)
        final_results.append(gsb_result)
        # ... (optional early exit logic) ...
    else:
        _log_lp("COMPREHENSIVE_SCAN: Google Safe Browsing checks skipped or API key missing.")

    # 3. Metadefender Cloud
    if app_settings.ENABLE_METADEFENDER_CHECKS and app_settings.METADEFENDER_API_KEY and "YOUR_METADEFENDER" not in app_settings.METADEFENDER_API_KEY:
        md_result = get_url_reputation_metadefender(url_to_check)
        final_results.append(md_result)
        # ... (optional early exit logic) ...
    else:
        _log_lp("COMPREHENSIVE_SCAN: Metadefender checks skipped or API key missing.")

    if not final_results:
        _log_lp(f"COMPREHENSIVE_SCAN: No security checks enabled or performed for {url_to_check[:70]}.")
        return [{"status": "No Security Scans Enabled/Configured", "source": "System", "positives":0, "total_scans":0, "details_link":"#"}] 
    
    _log_lp(f"COMPREHENSIVE_SCAN: Finished all enabled checks for {url_to_check[:70]}. Collected {len(final_results)} results.")
    return final_results

def is_likely_paywall(url, html_content=None):
    paywall_indicators_set = set(ind.lower() for ind in app_settings.PAYWALL_INDICATORS) # MODIFIED app_settings
    url_lower = url.lower()
    if any(indicator in url_lower for indicator in paywall_indicators_set):
        return True
    if html_content is None and app_settings.FETCH_EXTERNAL_LINK_HTML: # MODIFIED app_settings
        try:
            headers = {'User-Agent': app_settings.USER_AGENT_FOR_REQUESTS} # MODIFIED app_settings
            response = requests.get(url, timeout=app_settings.EXTERNAL_LINK_HTML_FETCH_TIMEOUT, headers=headers, allow_redirects=True) # MODIFIED app_settings
            response.raise_for_status()
            html_content = response.text
        except requests.RequestException as e:
            html_content = None
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        paywall_selectors = [
            "[class*='paywall']", "[id*='paywall']",
            "[class*='subscribe-prompt']", "[id*='subscribe-prompt']",
            "[class*='metered']", "[class*='gate']"
        ]
        for selector in paywall_selectors:
            if soup.select_one(selector):
                return True
        text_content = soup.get_text(separator=" ", strip=True).lower()
        matches = 0
        for indicator in paywall_indicators_set:
            if indicator in text_content:
                matches += text_content.count(indicator)
        if matches > 2 or any(strong_ind in text_content for strong_ind in ["to continue reading", "unlock all access", "full access with a subscription"]):
            return True
    return False