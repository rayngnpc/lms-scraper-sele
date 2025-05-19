# lms_auditor/core/lms_handler.py
import os
import time
import re
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
import requests
import traceback

from lms_auditor.config import app_settings
from .web_driver_setup import get_cookies_for_requests_from_driver

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException

log_queue = getattr(app_settings, 'LOG_QUEUE', None)

def _log_message(message):
    if log_queue and hasattr(log_queue, 'put'):
        log_queue.put(message)
    else:
        print(message, end='')

def get_page_html_with_selenium(driver, url, quick_grab_html_only=False, is_dashboard_page=False):
    _log_message(f"  Navigating (Selenium): {url[:100]}... (QuickGrab: {quick_grab_html_only}, Dashboard: {is_dashboard_page})\n")
    try:
        driver.get(url)
        if quick_grab_html_only:
            try:
                WebDriverWait(driver, 3).until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            except TimeoutException:
                _log_message(f"    Quick grab: Body tag not found quickly for {url}, getting source anyway.\n")
        elif is_dashboard_page:
            wait_time_dashboard = float(getattr(app_settings, 'SELENIUM_DASHBOARD_WAIT_SECONDS', 20))
            dashboard_content_selector = getattr(app_settings, 'MOODLE_DASHBOARD_COURSE_LIST_LOADED_SELECTOR', None) or None

            _log_message(f"    Dashboard page detected. Waiting for readyState (up to {wait_time_dashboard/2.0:.1f}s)...\n")
            try:
                WebDriverWait(driver, wait_time_dashboard / 2.0).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )
                _log_message("    Dashboard: Page readyState is complete.\n")
            except TimeoutException:
                _log_message(f"    Dashboard: Page {url[:70]} did not reach readyState 'complete' quickly. Continuing wait.\n")

            if dashboard_content_selector:
                _log_message(f"    Dashboard: Waiting for specific content element '{dashboard_content_selector}' (up to {wait_time_dashboard:.1f}s)...\n")
                try:
                    WebDriverWait(driver, wait_time_dashboard).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, dashboard_content_selector))
                    )
                    _log_message(f"    Dashboard: Content element '{dashboard_content_selector}' found.\n")
                    time.sleep(1)
                except TimeoutException:
                    _log_message(f"    WARNING: Dashboard specific content '{dashboard_content_selector}' NOT found after {wait_time_dashboard:.1f}s.\n")
            else:
                remaining_wait = wait_time_dashboard / 2.0
                _log_message(f"    Dashboard: No specific content selector. Applying general wait of {remaining_wait:.1f}s after readyState attempt.\n")
                time.sleep(remaining_wait)
                _log_message(f"    Dashboard: General wait completed.\n")
        else: 
            default_wait = float(getattr(app_settings, 'SELENIUM_DEFAULT_FULL_LOAD_WAIT', 7))
            path_lower = urlparse(url).path.lower()
            file_ext = os.path.splitext(path_lower)[1].lower()
            downloadable_exts = getattr(app_settings, 'DOWNLOADABLE_EXTENSIONS', [])
            if file_ext and downloadable_exts and file_ext in downloadable_exts:
                effective_wait = min(default_wait, 2.0)
                _log_message(f"    Likely direct file link detected, reducing wait to {effective_wait:.1f}s.\n")
            else:
                effective_wait = default_wait
            _log_message(f"    Waiting for page load (readyState, up to {effective_wait:.1f}s): {url[:70]}...\n")
            try:
                WebDriverWait(driver, effective_wait).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )
                _log_message("    Page readyState is complete.\n")
                time.sleep(0.5)
            except TimeoutException:
                _log_message(f"    Page {url[:70]} did not reach readyState 'complete' in {effective_wait:.1f}s. Proceeding anyway.\n")

        page_html = driver.page_source
        final_url = driver.current_url
        _log_message(f"  HTML source obtained for: {final_url[:100]} (Length: {len(page_html)})\n")
        return page_html, final_url
    except Exception as e_nav:
        err_msg = f"    ERROR navigating/processing {url[:100]} with Selenium: {e_nav}\n"
        _log_message(err_msg)
        current_url_on_error = url
        try: current_url_on_error = driver.current_url
        except Exception: pass
        return None, current_url_on_error

def get_course_name_from_page(page_html, course_url):
    if not page_html: return None
    soup = BeautifulSoup(page_html, 'html.parser')
    name_candidates = []
    specific_selectors = getattr(app_settings, 'COURSE_NAME_SELECTORS', [
        'header#page-header h1', 'div.page-header-headings h1', 'h1[data-region="course-title"]',
        '.h2.font-weight-bold[data-region="course-title"]', 'h1.title',
        'span.breadcrumb-item.active span[aria-current="page"]'
    ])
    for selector in specific_selectors:
        tag = soup.select_one(selector)
        if tag:
            txt = tag.get_text(strip=True)
            if txt and 3 < len(txt) < 150 and not any(skip.lower() in txt.lower() for skip in ["my courses", "dashboard", "site home", "participants", "grades", "log in to the site"]):
                site_name_from_domain = app_settings.LMS_SPECIFIC_DOMAIN.split('.')[0] if app_settings.LMS_SPECIFIC_DOMAIN else "Moodle"
                if site_name_from_domain.lower() not in txt.lower() or len(txt.replace(site_name_from_domain, "").strip()) > 5:
                    name_candidates.append(txt); break
    if not name_candidates:
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            title_text = title_tag.string.strip()
            site_name_pattern = app_settings.LMS_SPECIFIC_DOMAIN.split('.')[0] if app_settings.LMS_SPECIFIC_DOMAIN else "Moodle"
            name = re.sub(r'\s*[-|–—]\s*(' + re.escape(site_name_pattern) + r'|Moodle|Dashboard|My home|My courses|Courses)$', '', title_text, flags=re.IGNORECASE).strip()
            name = re.sub(r'^(Course|Courses|Unit|Subject):\s*', '', name, count=1, flags=re.IGNORECASE).strip()
            if name and 3 < len(name) < 150 and name.lower() not in ["dashboard", "my home", "my courses", site_name_pattern.lower(), "courses"]:
                 name_candidates.append(name)
    if not name_candidates:
        heading_selectors = ['h1', 'h2']
        for selector in heading_selectors:
            tags = soup.select(selector)
            for tag in tags:
                txt = tag.get_text(strip=True)
                if txt and 4 < len(txt) < 150 and not any(gen_txt.lower() in txt.lower() for gen_txt in ["dashboard", "my courses", "site home", "participants", "grades", "log in", "navigation", "skip", "general", "overview", "course categories"]):
                    name_candidates.append(txt)
                    if selector == 'h1': break
            if name_candidates and selector == 'h1': break
    if name_candidates:
        name_candidates = [n for n in name_candidates if not (n.lower().startswith("course_id_") and len(n) < 20)]
        name_candidates = [n for n in name_candidates if n.lower() not in ["general", "overview", "course overview", "topic outline"]]
        if name_candidates:
             best_name = max(name_candidates, key=lambda n: (sum(c.isalpha() for c in n), len(n)))
             return "".join(c for c in best_name if c.isalnum() or c in (' ', '_', '-', ':', '&', '(', ')', "'", "%", "+", ",", "."))[:150].strip()
    p_url = urlparse(course_url); id_m = re.search(r'id=(\d+)', p_url.query or "")
    c_id = id_m.group(1) if id_m else "unknown_id"
    return f"Course_ID_{c_id}"

def download_file_via_requests(file_url, target_filename_base, driver, source_page_url="UnknownSource", file_ext_hint=None):
    _log_message(f"  Attempting download (requests): {file_url[:100]}... as '{target_filename_base[:50]}'\n")
    file_save_base_dir = os.path.join(app_settings.MAIN_OUTPUT_DIRECTORY, getattr(app_settings, 'FILES_SUBDIR', 'downloaded_files'))
    source_path_slug = "misc_files"
    if source_page_url and source_page_url not in ["UnknownSource", "SELF_IS_FILE"]:
        try:
            parsed_source_url = urlparse(source_page_url)
            path_components = [comp for comp in parsed_source_url.path.strip('/').split('/') if comp]
            slug_parts = [("".join(c for c in comp if c.isalnum() or c in ('_', '-')).strip()[:30]) for comp in path_components[:2] if comp]
            if slug_parts: source_path_slug = "_".join(filter(None, slug_parts))
            elif parsed_source_url.query:
                query_id_match = re.search(r'id=(\w+)', parsed_source_url.query)
                if query_id_match: source_path_slug = f"page_id_{query_id_match.group(1)}"
            if not source_path_slug: source_path_slug = "misc_files" # Fallback if logic above fails
        except Exception: pass # Keep source_path_slug as "misc_files" on error
    dl_dir = os.path.join(file_save_base_dir, source_path_slug)
    os.makedirs(dl_dir, exist_ok=True)

    current_filename_base = target_filename_base
    try:
        url_path_name_decoded = unquote(os.path.basename(urlparse(file_url).path))
        if url_path_name_decoded: current_filename_base = url_path_name_decoded
    except Exception: pass

    if not isinstance(current_filename_base, str):
        current_filename_base = f"file_from_invalid_base_{int(time.time())}"
    
    current_filename_base = current_filename_base.replace('…', '_')
    current_filename_base = re.sub(r'\.{2,}', '_', current_filename_base)
    current_filename_base = "".join(c for c in current_filename_base if c.isalnum() or c in ('.', '_', '-', ' ', '(', ')')).strip()
    current_filename_base = re.sub(r'\s+', '_', current_filename_base)
    current_filename_base = current_filename_base.strip('._')

    if not current_filename_base:
        current_filename_base = f"sanitized_empty_fallback_{int(time.time())}"

    name_part, ext_part = os.path.splitext(current_filename_base)
    if not ext_part:
        if file_ext_hint and file_ext_hint.startswith('.'): ext_part = file_ext_hint
        else:
            _, url_ext_original = os.path.splitext(urlparse(file_url).path)
            if url_ext_original and url_ext_original.lower() in getattr(app_settings, 'DOWNLOADABLE_EXTENSIONS', []):
                ext_part = url_ext_original
    if not name_part and ext_part: name_part = f"file_no_name_part_{int(time.time())}"
    if not name_part: name_part = f"default_name_{int(time.time())}"

    safe_fname_final_base = name_part + ext_part
    max_fname_len = getattr(app_settings, 'MAX_FILENAME_LENGTH', 200)
    if len(safe_fname_final_base) > max_fname_len:
        name_p, ext_p = os.path.splitext(safe_fname_final_base)
        name_p = name_p[:max_fname_len - len(ext_p) - (1 if ext_p else 0)]
        safe_fname_final_base = name_p + ext_p
    if not os.path.splitext(safe_fname_final_base)[0]:
        safe_fname_final_base = f"truncated_empty_name_{int(time.time())}{os.path.splitext(safe_fname_final_base)[1]}"

    local_fpath = os.path.join(dl_dir, safe_fname_final_base)
    counter = 1
    original_local_fpath_for_collision = local_fpath
    while os.path.exists(local_fpath):
        name, ext = os.path.splitext(os.path.basename(original_local_fpath_for_collision))
        coll_fname = f"{name}_{counter}{ext}"
        if len(coll_fname) > max_fname_len:
            name = name[:max_fname_len - len(ext) - len(str(counter)) - 2]
            coll_fname = f"{name}_{counter}{ext}"
        local_fpath = os.path.join(dl_dir, coll_fname)
        counter += 1
        if counter > 50:
            _log_message(f"  Too many filename collisions for: {original_local_fpath_for_collision}. Aborting download.\n")
            return {'type': 'error', 'success': False, 'message': 'Too many filename collisions',
                    'original_url': file_url, 'filename': os.path.basename(original_local_fpath_for_collision)}

    dl_result = {'type': 'error', 'success': False, 'message': 'Download not attempted or failed early',
                 'original_url': file_url, 'filename': os.path.basename(local_fpath), 'local_path': None}
    try:
        headers = {"User-Agent": getattr(app_settings, 'USER_AGENT_FOR_REQUESTS', 'Mozilla/5.0')}
        req_cookies = get_cookies_for_requests_from_driver(driver)
        response = requests.get(file_url, headers=headers, cookies=req_cookies, stream=True, timeout=180, allow_redirects=True)
        final_dl_url = response.url

        content_disposition = response.headers.get('Content-Disposition')
        if content_disposition:
            disp_fname_match = re.search(r'filename\*?=(?:UTF-\d[\'\"]*)?([^\r\n\'";]+)[\r\n\'";]*', content_disposition, re.IGNORECASE)
            if disp_fname_match:
                disp_fname_raw = disp_fname_match.group(1); disp_fname = unquote(disp_fname_raw).strip().strip('"')
                if disp_fname:
                    new_safe_fname_base_cd = disp_fname.replace('…', '_')
                    new_safe_fname_base_cd = re.sub(r'\.{2,}', '_', new_safe_fname_base_cd)
                    new_safe_fname_base_cd = "".join(c for c in new_safe_fname_base_cd if c.isalnum() or c in ('.', '_', '-', ' ', '(', ')')).strip()
                    new_safe_fname_base_cd = re.sub(r'\s+', '_', new_safe_fname_base_cd).strip('._')
                    if new_safe_fname_base_cd:
                        if len(new_safe_fname_base_cd) > max_fname_len:
                            np_temp, ep_temp = os.path.splitext(new_safe_fname_base_cd)
                            np_temp = np_temp[:max_fname_len - len(ep_temp) - (1 if ep_temp else 0)]
                            new_safe_fname_base_cd = np_temp + ep_temp
                        
                        local_fpath_cd = os.path.join(dl_dir, new_safe_fname_base_cd)
                        counter_cd = 1
                        original_local_fpath_cd_coll = local_fpath_cd
                        while os.path.exists(local_fpath_cd):
                            name_cd, ext_cd = os.path.splitext(os.path.basename(original_local_fpath_cd_coll))
                            coll_fname_cd = f"{name_cd}_{counter_cd}{ext_cd}"
                            if len(coll_fname_cd) > max_fname_len:
                                name_cd = name_cd[:max_fname_len - len(ext_cd) - len(str(counter_cd)) - 2]
                                coll_fname_cd = f"{name_cd}_{counter_cd}{ext_cd}"
                            local_fpath_cd = os.path.join(dl_dir, coll_fname_cd)
                            counter_cd += 1
                            if counter_cd > 50: break
                        if counter_cd <= 50: local_fpath = local_fpath_cd
                        dl_result['filename'] = os.path.basename(local_fpath)

        ct_dl = response.headers.get('Content-Type', '').lower().split(';')[0].strip()
        response.raise_for_status()
        peek_content_data = b""
        if 'text/html' in ct_dl and response.status_code == 200:
            try:
                for chunk in response.iter_content(chunk_size=2048, decode_unicode=False):
                    peek_content_data += chunk
                    if len(peek_content_data) >= 2048: break
            except Exception as e_peek: _log_message(f"  Warning: Error peeking into response stream: {e_peek}\n")
            if b"<html" in peek_content_data.lower() and (b"<head" in peek_content_data.lower() or b"<body" in peek_content_data.lower()):
                 if any(kw.encode('utf-8', 'ignore') in peek_content_data.lower() for kw in ["error", "login", "not found", "access denied", "forbidden", "requires authentication", "log in to the site"]):
                    _log_message(f"  Warning: Expected file from {file_url}, received HTML (likely error/login page). Content: {peek_content_data[:200]}...\n")
                    dl_result.update({'message': 'Expected file, got HTML error/login page', 'final_url': final_dl_url, 'status_message': 'HTML Error Page'})
                    return dl_result
        with open(local_fpath, 'wb') as f:
            if peek_content_data: f.write(peek_content_data)
            for chunk in response.iter_content(chunk_size=1024 * 256):
                if chunk: f.write(chunk)
        if os.path.exists(local_fpath) and os.path.getsize(local_fpath) > 0:
            _log_message(f"  Downloaded (requests): '{os.path.basename(local_fpath)}' to '{dl_dir}'\n")
            dl_result.update({'type': 'file', 'success': True, 'status': 'downloaded', 'local_path': local_fpath, 'filename': os.path.basename(local_fpath), 'final_url': final_dl_url})
            ### MODIFIED: REMOVED IMMEDIATE SCAN ###
            # if dl_result['success'] and app_settings.ENABLE_LOCAL_FILE_SCANS:
            #     dl_result['scan_result'] = scan_file_locally(local_fpath) # This line is removed
        else:
            _log_message(f"  Download attempt for {file_url} resulted in empty/non-existent file: {local_fpath}\n")
            dl_result.update({'message': 'File empty or not created after download attempt', 'status_message': 'Empty/Missing File'})
        return dl_result
    except requests.exceptions.Timeout:
        _log_message(f"  TIMEOUT downloading {file_url}\n")
        dl_result.update({'message': 'Timeout', 'status_message': 'Timeout'})
        return dl_result
    except requests.exceptions.HTTPError as http_err:
        _log_message(f"  HTTP ERROR {http_err.response.status_code} downloading {file_url}: {http_err}\n")
        dl_result.update({'message': f"HTTP Error: {http_err.response.status_code} {http_err.response.reason}", 'final_url': getattr(http_err.response, 'url', file_url), 'status_message': f'HTTP Error {http_err.response.status_code}'})
        return dl_result
    except requests.exceptions.RequestException as req_err:
        _log_message(f"  REQUEST ERROR downloading {file_url}: {req_err}\n")
        dl_result.update({'message': f"Request Error: {str(req_err)}", 'status_message': 'Request Error'})
        return dl_result
    except Exception as e_g:
        _log_message(f"  UNEXPECTED ERROR downloading {file_url}: {e_g}\n")
        traceback.print_exc()
        dl_result.update({'message': f"Unexpected Error: {str(e_g)}", 'status_message': 'Unexpected Download Error'})
        return dl_result