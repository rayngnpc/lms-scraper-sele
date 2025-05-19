# lms_auditor/core/auditor.py
import time
import threading
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import os
import hashlib
import re
from datetime import datetime
import traceback

from .report_services import (
    generate_course_audit_summary_csv,
    save_data_to_json_file,
    generate_detailed_course_report,
    generate_main_index_html
)

from lms_auditor.config import app_settings

from .web_driver_setup import initialize_driver
from .lms_handler import get_page_html_with_selenium, get_course_name_from_page, download_file_via_requests
from .link_processor import categorize_link, get_comprehensive_url_reputation, is_likely_paywall # get_url_reputation_virustotal is now called by get_comprehensive_url_reputation
from .reference_handler import ReferenceManager

from lms_auditor.clamav.scanner_control import scan_directory_and_map_results

gui_continue_event = None
gui_stop_event = None

def _log_message_auditor(message_content):
    try:
        q = app_settings.LOG_QUEUE
        if q and hasattr(q, 'put'):
            q.put(str(message_content) + "\n")
            return
    except AttributeError:
        pass
    print(str(message_content), flush=True)


def set_events_from_gui(continue_event_from_gui, stop_event_from_gui):
    global gui_continue_event, gui_stop_event
    gui_continue_event = continue_event_from_gui
    gui_stop_event = stop_event_from_gui
    _log_message_auditor(f"DEBUG_MAIN_MODULE: set_events_from_gui called.")
    _log_message_auditor(f"  ContinueEvent is_set: {gui_continue_event.is_set() if gui_continue_event else 'N/A'}")
    _log_message_auditor(f"  StopEvent is_set: {gui_stop_event.is_set() if gui_stop_event else 'N/A'}")

def create_and_set_timestamped_output_dir():
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_output_dir = app_settings.MAIN_OUTPUT_DIRECTORY_BASE
    if not os.path.isabs(base_output_dir):
        base_output_dir = os.path.abspath(base_output_dir)
        _log_message_auditor(f"INFO: MAIN_OUTPUT_DIRECTORY_BASE was relative, converted to absolute: {base_output_dir}")

    current_run_output_dir = os.path.join(base_output_dir, f"audit_run_{timestamp_str}")
    app_settings.MAIN_OUTPUT_DIRECTORY = current_run_output_dir
    _log_message_auditor(f"INFO: Output directory for this run set to: {app_settings.MAIN_OUTPUT_DIRECTORY}")

    reports_main_dir = os.path.join(app_settings.MAIN_OUTPUT_DIRECTORY, app_settings.REPORTS_SUBDIR)
    course_html_reports_subdir_name = getattr(app_settings, 'COURSE_HTML_REPORTS_SUBDIR_NAME', 'detailed_course_reports')
    course_html_reports_path = os.path.join(reports_main_dir, course_html_reports_subdir_name)

    paths_to_create = [
        app_settings.MAIN_OUTPUT_DIRECTORY,
        os.path.join(app_settings.MAIN_OUTPUT_DIRECTORY, app_settings.HTML_SUBDIR),
        os.path.join(app_settings.MAIN_OUTPUT_DIRECTORY, app_settings.FILES_SUBDIR),
        reports_main_dir,
        course_html_reports_path,
        os.path.join(app_settings.MAIN_OUTPUT_DIRECTORY, app_settings.SELENIUM_BROWSER_DL_SUBDIR)
    ]
    for path in paths_to_create:
        if path and path.strip():
            if not os.path.exists(path):
                _log_message_auditor(f"Creating directory: {path}")
                os.makedirs(path, exist_ok=True)
            else:
                _log_message_auditor(f"Directory already exists: {path}")


def audit_lms_courses_fully():
    global gui_continue_event, gui_stop_event
    driver = None
    _log_message_auditor(f"AUDIT_PROCESS: Starting audit_lms_courses_fully.")

    if gui_stop_event and gui_stop_event.is_set():
        _log_message_auditor("AUDIT_PROCESS: Stop event ALREADY SET at start. Aborting.")
        return

    try:
        create_and_set_timestamped_output_dir()
        driver = initialize_driver()
        if driver is None:
            _log_message_auditor("AUDIT_PROCESS_ERROR: Failed to initialize WebDriver. Exiting.")
            return

        overall_course_audit_data = []
        ref_manager = ReferenceManager()

        if gui_stop_event and gui_stop_event.is_set(): _log_message_auditor("AUDIT_PROCESS: Stop signal after init. Aborting."); return

        _log_message_auditor(f"AUDIT_PROCESS: Navigating to Moodle Login URL: {app_settings.MOODLE_LOGIN_URL}")
        driver.get(app_settings.MOODLE_LOGIN_URL)
        time.sleep(2)

        login_prompt_message = ("\n" + "="*80 + "\nACTION REQUIRED: MANUALLY LOG IN to Moodle.\n"
                                "IMPORTANT: After logging in, please MANUALLY NAVIGATE in the browser\n"
                                "to the page that lists ALL your courses (e.g., '/my/courses.php' or similar).\n"
                                "Then, use the 'Continue After Login' button in the GUI.\n" + "="*80 + "\n")
        _log_message_auditor(login_prompt_message)

        if gui_continue_event:
            _log_message_auditor("AUDIT_PROCESS: Waiting for 'Continue After Login' signal from GUI...")
            while not gui_continue_event.is_set():
                if gui_stop_event and gui_stop_event.is_set(): _log_message_auditor("AUDIT_PROCESS: Stop signal while waiting for login. Aborting."); return
                time.sleep(0.2)
            _log_message_auditor("AUDIT_PROCESS: 'Continue After Login' signal received. Proceeding.")
            gui_continue_event.clear()
        else:
            input("Press Enter in CONSOLE to continue after manual login and navigation to course list page...")

        if gui_stop_event and gui_stop_event.is_set(): _log_message_auditor("AUDIT_PROCESS: Stop signal after login. Aborting."); return

        dashboard_url_for_parsing = driver.current_url
        _log_message_auditor(f"AUDIT_PROCESS: Discovering courses from current page: {dashboard_url_for_parsing}")
        dashboard_html, final_grabbed_dashboard_url = get_page_html_with_selenium(driver, dashboard_url_for_parsing, quick_grab_html_only=False, is_dashboard_page=True)
        base_url_for_dashboard_links = final_grabbed_dashboard_url if final_grabbed_dashboard_url else dashboard_url_for_parsing

        if not dashboard_html:
            _log_message_auditor(f"AUDIT_PROCESS_ERROR: Could not retrieve HTML from ({base_url_for_dashboard_links}). Exiting.")
            return

        dashboard_soup = BeautifulSoup(dashboard_html, 'html.parser')
        potential_links_info = []
        temp_dash_urls_processed = set()

        css_selectors_courses = getattr(app_settings, 'COURSE_LINK_CSS_SELECTORS', [
            'div.coursebox > div.info > h3.coursename a[href*="/course/view.php?id="]',
            'li.course-list-item a.aalink.coursename[href*="/course/view.php?id="]',
            'div.dashboard-card a.aalink[href*="/course/view.php?id="]',
            'div[data-region="course-summary-container"] a[href*="/course/view.php?id="]',
            'a.list-group-item[href*="/course/view.php?id="]',
            'div.card.dashboard-card [data-type="link"][href*="/course/view.php?id="]',
            '.media-body > .mt-0 > a[href*="/course/view.php?id="]',
            'h4.media-heading > a[href*="/course/view.php?id="]',
            'a[href*="/course/view.php?id="][title*="course"]'])
        course_elements = []
        for selector in css_selectors_courses:
            if gui_stop_event and gui_stop_event.is_set(): break
            elements = dashboard_soup.select(selector)
            if elements: course_elements.extend(elements)

        if not course_elements and not (gui_stop_event and gui_stop_event.is_set()):
             _log_message_auditor("AUDIT_PROCESS: Specific course link selectors failed, trying broader 'a[href*=\"/course/view.php?id=\"]'...")
             course_elements = dashboard_soup.find_all('a', href=re.compile(r'/course/view\.php\?id=\d+'))

        dashboard_link_skip_texts = getattr(app_settings, 'DASHBOARD_LINK_SKIP_TEXT',
                                            ["my courses", "all courses", "site home", "help", "support", "profile"])
        ignore_course_id_1 = getattr(app_settings, 'IGNORE_COURSE_ID_1', True)

        for link_tag in course_elements:
            if gui_stop_event and gui_stop_event.is_set(): break
            href = link_tag.get('href')
            text = link_tag.get_text(strip=True) or "NoTextOnLink"
            if not href: continue

            abs_url = urljoin(base_url_for_dashboard_links, href)
            parsed_abs_url = urlparse(abs_url)

            is_valid_course_link = True
            if app_settings.LMS_SPECIFIC_DOMAIN not in parsed_abs_url.netloc: is_valid_course_link = False
            if "/course/view.php?id=" not in abs_url: is_valid_course_link = False
            if ignore_course_id_1 and parsed_abs_url.query and "id=1" in parsed_abs_url.query:
                 is_valid_course_link = False
            if any(skip_text in text.lower() for skip_text in dashboard_link_skip_texts): is_valid_course_link = False

            if is_valid_course_link:
                if abs_url not in temp_dash_urls_processed:
                    potential_links_info.append({'url': abs_url, 'dash_text': text})
                    temp_dash_urls_processed.add(abs_url)

        if gui_stop_event and gui_stop_event.is_set(): _log_message_auditor("AUDIT_PROCESS: Stop signal during course link processing. Aborting."); return

        _log_message_auditor(f"AUDIT_PROCESS: Found {len(potential_links_info)} unique potential course links from dashboard. Verifying...")
        discovered_courses = []
        processed_final_course_urls = set()
        for i, info_item in enumerate(potential_links_info):
            if gui_stop_event and gui_stop_event.is_set(): break
            curl_to_verify = info_item['url']
            _log_message_auditor(f"AUDIT_PROCESS: Verifying course ({i+1}/{len(potential_links_info)}): {curl_to_verify[:100]}...")

            html_course_page, final_course_url = get_page_html_with_selenium(driver, curl_to_verify, quick_grab_html_only=False)

            if not html_course_page or \
               app_settings.LMS_SPECIFIC_DOMAIN not in urlparse(final_course_url).netloc or \
               not ("/course/view.php?id=" in final_course_url or "/course/info.php?id=" in final_course_url):
                _log_message_auditor(f"AUDIT_PROCESS: Skipping {curl_to_verify} (Not valid Moodle course. Final URL: {final_course_url}).")
                continue

            if final_course_url in processed_final_course_urls:
                _log_message_auditor(f"AUDIT_PROCESS: Skipping {curl_to_verify} (final URL {final_course_url} already processed).")
                continue
            processed_final_course_urls.add(final_course_url)

            course_name_from_page = get_course_name_from_page(html_course_page, final_course_url)
            if not course_name_from_page or "Course_ID_" in course_name_from_page:
                fb_html = f"<html><head><title>{info_item['dash_text']}</title></head><body><h1>{info_item['dash_text']}</h1></body></html>"
                cname_fb = get_course_name_from_page(fb_html, final_course_url)
                if cname_fb and "Course_ID_" not in cname_fb and len(cname_fb) > 3:
                    course_name_from_page = cname_fb
                else:
                    id_m = re.search(r'id=(\d+)', final_course_url)
                    cid = id_m.group(1) if id_m else "uid"
                    safe_txt = "".join(c for c in info_item['dash_text'][:25] if c.isalnum() or c=='_')
                    course_name_from_page = f"Course_{cid}_{safe_txt}".strip('_')[:100]

            _log_message_auditor(f"AUDIT_PROCESS: Identified Course: '{course_name_from_page}' (URL: {final_course_url})")
            discovered_courses.append({'name': course_name_from_page, 'url': final_course_url})
            if not (gui_stop_event and gui_stop_event.is_set()): time.sleep(0.1)

        if gui_stop_event and gui_stop_event.is_set(): _log_message_auditor("AUDIT_PROCESS: Stop signal after course verification. Aborting."); return

        if not discovered_courses and not (gui_stop_event and gui_stop_event.is_set()):
            _log_message_auditor("AUDIT_PROCESS: No valid courses identified from dashboard. Exiting course processing.")
        elif discovered_courses:
            _log_message_auditor(f"AUDIT_PROCESS: Processing {len(discovered_courses)} identified courses.")
            for current_course_info in discovered_courses:
                if gui_stop_event and gui_stop_event.is_set():
                    _log_message_auditor(f"AUDIT_PROCESS: Stop signal before processing course {current_course_info.get('name')}.")
                    break

                course_name, course_main_url = current_course_info['name'], current_course_info['url']
                _log_message_auditor(f"AUDIT_PROCESS: --- Processing Course: '{course_name}' ({course_main_url[:80]}) ---")

                q = [(course_main_url, course_main_url)]
                visited_this_course_pages = set()
                processed_file_urls_this_course = set()
                
                link_type_keys_setting = getattr(app_settings, 'LINK_TYPE_KEYS_FOR_COUNTING', [])
                link_type_keys = link_type_keys_setting if isinstance(link_type_keys_setting, list) else []
                counts_this_course = {k:0 for k in link_type_keys}
                
                downloaded_for_this_course_details = []
                external_links_raw_details_this_course = []
                crawled_count_this_course = 0
                max_pages_per_course_config = int(getattr(app_settings, 'MAX_PAGES_TO_CRAWL_PER_COURSE', 1))

                while q and crawled_count_this_course < max_pages_per_course_config:
                    if gui_stop_event and gui_stop_event.is_set():
                        _log_message_auditor(f"AUDIT_PROCESS: Stop signal during page crawling for {course_name}.")
                        break
                    
                    curr_c_pg_url_to_visit, source_page_of_curr_url = q.pop(0)
                    if curr_c_pg_url_to_visit in visited_this_course_pages: continue

                    should_quick_grab_content = getattr(app_settings, 'ENABLE_QUICK_GRAB_CONTENT_PAGES', False)
                    html_page_content, final_c_pg_url = get_page_html_with_selenium(driver, curr_c_pg_url_to_visit, quick_grab_html_only=should_quick_grab_content)

                    if not html_page_content:
                        visited_this_course_pages.add(curr_c_pg_url_to_visit)
                        if final_c_pg_url != curr_c_pg_url_to_visit: visited_this_course_pages.add(final_c_pg_url)
                        continue
                    if final_c_pg_url in visited_this_course_pages:
                        if curr_c_pg_url_to_visit != final_c_pg_url: visited_this_course_pages.add(curr_c_pg_url_to_visit)
                        continue

                    visited_this_course_pages.add(final_c_pg_url)
                    if curr_c_pg_url_to_visit != final_c_pg_url: visited_this_course_pages.add(curr_c_pg_url_to_visit)
                    crawled_count_this_course += 1
                    _log_message_auditor(f"AUDIT_PROCESS:   Page {crawled_count_this_course}/{max_pages_per_course_config}: {final_c_pg_url[:80]}...")

                    if app_settings.LMS_SPECIFIC_DOMAIN not in urlparse(final_c_pg_url).netloc: continue

                    p_final_parsed_page = urlparse(final_c_pg_url)
                    hash_v_page = hashlib.md5(final_c_pg_url.encode('utf-8')).hexdigest()[:10]
                    path_page_slug_page = "_".join(p_final_parsed_page.path.strip('/').split('/')[:2])
                    path_page_slug_page = "".join(c for c in path_page_slug_page if c.isalnum() or c in ('_','-')).rstrip('_')[:40]
                    page_dir_name_page = f"{path_page_slug_page}_{hash_v_page}" if path_page_slug_page else hash_v_page
                    course_name_slug_page = "".join(c for c in course_name if c.isalnum() or c=='_')[:50]
                    
                    html_subdir_name = getattr(app_settings, 'HTML_SUBDIR', 'html_pages_per_course')
                    main_output_abs = os.path.abspath(app_settings.MAIN_OUTPUT_DIRECTORY)
                    html_save_dir_page = os.path.join(main_output_abs, html_subdir_name, p_final_parsed_page.netloc, course_name_slug_page, page_dir_name_page)
                    os.makedirs(html_save_dir_page, exist_ok=True)
                    try:
                        with open(os.path.join(html_save_dir_page, "index.html"), "w", encoding="utf-8") as f_html_p: f_html_p.write(html_page_content)
                        with open(os.path.join(html_save_dir_page, "url_ref.txt"), "w") as f_ref_p: f_ref_p.write(f"Original: {curr_c_pg_url_to_visit}\nFinal: {final_c_pg_url}\nSource: {source_page_of_curr_url}")
                    except Exception as e_sh: _log_message_auditor(f"AUDIT_PROCESS_ERROR:   ERR saving HTML for {final_c_pg_url}: {e_sh}")

                    cat_current_page_info = categorize_link(final_c_pg_url, final_c_pg_url)
                    page_type_is = cat_current_page_info['type']
                    page_file_ext_hint_is = cat_current_page_info.get('file_ext')

                    if page_type_is.startswith(('lms_file_', 'uni_file_')):
                        if page_type_is in counts_this_course: counts_this_course[page_type_is] += 1
                        if final_c_pg_url not in processed_file_urls_this_course:
                            processed_file_urls_this_course.add(final_c_pg_url)
                            fname_page_as_file_is = os.path.basename(p_final_parsed_page.path) or f"page_as_file_{int(time.time())}"
                            dl_res_is = download_file_via_requests(final_c_pg_url, fname_page_as_file_is, driver, source_page_url="SELF_IS_FILE", file_ext_hint=page_file_ext_hint_is)
                            dl_detail_is = {
                                "text": dl_res_is.get('filename', fname_page_as_file_is), "original_url": dl_res_is.get('original_url', final_c_pg_url),
                                "local_path": dl_res_is.get('local_path'), "filename": dl_res_is.get('filename'),
                                "source_page_url": "SELF_IS_FILE", "success": dl_res_is.get('success', False),
                                "status_message": dl_res_is.get('message', dl_res_is.get('status_message', dl_res_is.get('status', 'N/A')))
                            }
                            downloaded_for_this_course_details.append(dl_detail_is)
                        html_page_content = None

                    if not html_page_content: continue

                    soup_page_to_parse = BeautifulSoup(html_page_content, 'html.parser')
                    links_found_on_page = soup_page_to_parse.find_all('a', href=True)
                    new_lms_links_for_q = set()
                    for link_on_page in links_found_on_page:
                        if gui_stop_event and gui_stop_event.is_set(): break
                        raw_href_found = link_on_page['href']
                        link_text_on_page = link_on_page.get_text(strip=True) or "NoLinkText"
                        if not raw_href_found or raw_href_found.startswith(('#', 'javascript:', 'mailto:', 'tel:')): continue

                        abs_link_url_found = urljoin(final_c_pg_url, raw_href_found)
                        cat_link_details = categorize_link(abs_link_url_found, final_c_pg_url)
                        found_link_type = cat_link_details['type']
                        found_link_url_final = cat_link_details['url']
                        found_link_file_ext_hint = cat_link_details.get('file_ext')

                        if found_link_type == 'skip': continue
                        if found_link_type in counts_this_course: counts_this_course[found_link_type] += 1
                        else: counts_this_course[found_link_type] = 1

                        if found_link_type == 'lms_course_page':
                            is_other_main = any(found_link_url_final == other_c['url'] for other_c in discovered_courses if other_c['url'] != course_main_url)
                            can_be_queued_link = True
                            if found_link_url_final in visited_this_course_pages: can_be_queued_link = False
                            if found_link_url_final in [item[0] for item in q]: can_be_queued_link = False
                            if is_other_main: can_be_queued_link = False
                            if can_be_queued_link: new_lms_links_for_q.add(found_link_url_final)
                        elif found_link_type.startswith(('lms_file_', 'uni_file_')):
                            _log_message_auditor(f"  DEBUG_AUDITOR_FILE_CHECK: Checking file URL for download: {found_link_url_final}")
                            _log_message_auditor(f"  DEBUG_AUDITOR_FILE_CHECK: Current processed_file_urls_this_course: {processed_file_urls_this_course}")
                            if found_link_url_final not in processed_file_urls_this_course:
                                _log_message_auditor(f"  DEBUG_AUDITOR_FILE_CHECK: URL '{found_link_url_final}' NOT in set. Adding and downloading.")
                                processed_file_urls_this_course.add(found_link_url_final)
                                fname_linked_download = os.path.basename(urlparse(found_link_url_final).path) or link_text_on_page[:40].strip() or f"linked_f_{int(time.time())}"
                                dl_res_file_link = download_file_via_requests(found_link_url_final, fname_linked_download, driver, final_c_pg_url, found_link_file_ext_hint)
                                dl_detail_file_link = {
                                    "text": link_text_on_page, "original_url": dl_res_file_link.get('original_url', found_link_url_final),
                                    "local_path": dl_res_file_link.get('local_path'), "filename": dl_res_file_link.get('filename'),
                                    "source_page_url": final_c_pg_url, "success": dl_res_file_link.get('success', False),
                                    "status_message": dl_res_file_link.get('message', dl_res_file_link.get('status_message', dl_res_file_link.get('status', 'N/A')))
                                }
                                downloaded_for_this_course_details.append(dl_detail_file_link)
                            else:
                                _log_message_auditor(f"  DEBUG_AUDITOR_FILE_CHECK: URL '{found_link_url_final}' IS ALREADY in set. Skipping download.")
                        elif found_link_type.startswith('external_'):
                            external_links_raw_details_this_course.append({'url': found_link_url_final, 'type': found_link_type, 'text': link_text_on_page, 'source_page_url': final_c_pg_url})

                    if gui_stop_event and gui_stop_event.is_set(): break
                    for new_q_link in new_lms_links_for_q: q.append((new_q_link, final_c_pg_url))
                
                _log_message_auditor(f"DEBUG_AUDITOR: For course '{course_name}', ENABLE_LOCAL_FILE_SCANS is {app_settings.ENABLE_LOCAL_FILE_SCANS}")
                _log_message_auditor(f"DEBUG_AUDITOR: For course '{course_name}', number of downloaded_for_this_course_details: {len(downloaded_for_this_course_details)}")
                
                if app_settings.ENABLE_LOCAL_FILE_SCANS and downloaded_for_this_course_details and not (gui_stop_event and gui_stop_event.is_set()):
                    _log_message_auditor(f"AUDIT_PROCESS:   Performing batch ClamAV scan for course '{course_name}' files...")
                    unique_course_dirs_to_scan = set()
                    for f_detail_for_dir in downloaded_for_this_course_details:
                        if f_detail_for_dir.get('success') and f_detail_for_dir.get('local_path'):
                            abs_local_path_for_dir = os.path.abspath(f_detail_for_dir['local_path'])
                            dir_path = os.path.dirname(abs_local_path_for_dir)
                            if dir_path: 
                                unique_course_dirs_to_scan.add(dir_path)
                    _log_message_auditor(f"DEBUG_AUDITOR: For course '{course_name}', unique_course_dirs_to_scan: {unique_course_dirs_to_scan}")
                    course_batch_scan_results_map = {} 
                    if not unique_course_dirs_to_scan and downloaded_for_this_course_details:
                         _log_message_auditor(f"AUDIT_PROCESS_WARN:   No valid directories identified for batch scan in course '{course_name}', though {len(downloaded_for_this_course_details)} download attempts were logged.")
                         for idx_debug_path, f_det_debug_path in enumerate(downloaded_for_this_course_details):
                             _log_message_auditor(f"  DEBUG_AUDITOR_PATHS: File {idx_debug_path} success: {f_det_debug_path.get('success')}, local_path: {f_det_debug_path.get('local_path')}, filename: {f_det_debug_path.get('filename')}")
                    for dir_to_scan in unique_course_dirs_to_scan:
                        if gui_stop_event and gui_stop_event.is_set(): _log_message_auditor(f"AUDIT_PROCESS: Stop signal during batch scan setup for {course_name}."); break
                        _log_message_auditor(f"AUDIT_PROCESS:     Attempting to scan directory: {dir_to_scan} for course {course_name}")
                        dir_results = scan_directory_and_map_results(dir_to_scan)
                        if dir_results: course_batch_scan_results_map.update(dir_results)
                        else: _log_message_auditor(f"AUDIT_PROCESS_WARN: No scan results returned for directory {dir_to_scan}")
                    _log_message_auditor(f"DEBUG_AUDITOR: For course '{course_name}', after scan calls, course_batch_scan_results_map has {len(course_batch_scan_results_map)} entries.")
                    if course_batch_scan_results_map:
                        for k_map_debug, v_map_debug in course_batch_scan_results_map.items():
                            _log_message_auditor(f"  DEBUG_AUDITOR_MAP_CONTENT: Key='{k_map_debug}', Status='{v_map_debug.get('status', 'N/A')}'")
                    if not (gui_stop_event and gui_stop_event.is_set()):
                        _log_message_auditor(f"DEBUG_AUDITOR: Attempting to update scan_result for {len(downloaded_for_this_course_details)} downloaded items in '{course_name}'.")
                        for f_idx, f_detail_update in enumerate(downloaded_for_this_course_details):
                            if f_detail_update.get('success') and f_detail_update.get('local_path'):
                                norm_path_to_lookup = os.path.normpath(os.path.abspath(f_detail_update['local_path']))
                                _log_message_auditor(f"  DEBUG_AUDITOR_UPDATE_ITEM {f_idx}: File='{f_detail_update.get('filename', 'N/A')}', NormPathLookup='{norm_path_to_lookup}'")
                                if norm_path_to_lookup in course_batch_scan_results_map:
                                    f_detail_update['scan_result'] = course_batch_scan_results_map[norm_path_to_lookup]
                                    _log_message_auditor(f"    DEBUG_AUDITOR_UPDATE_ITEM {f_idx}: MATCH FOUND in map. New scan_status: '{f_detail_update['scan_result'].get('status')}'")
                                else:
                                    f_detail_update['scan_result'] = {
                                        "status": "ScanDataMissingInBatch", "infected": None,
                                        "details": f"File result for ABSOLUTE path '{norm_path_to_lookup}' not found in course batch scan map. Map keys checked: {len(course_batch_scan_results_map)}.",
                                        "needs_freshclam": False
                                    }
                                    _log_message_auditor(f"    DEBUG_AUDITOR_UPDATE_ITEM {f_idx}: NO MATCH for '{norm_path_to_lookup}'. Set to ScanDataMissingInBatch. Example map keys: {list(course_batch_scan_results_map.keys())[:10]}")
                            else:
                                _log_message_auditor(f"  DEBUG_AUDITOR_UPDATE_ITEM {f_idx}: File='{f_detail_update.get('filename', 'N/A')}', not successful or no local_path. Skipping scan update.")
                            _log_message_auditor(f"  DEBUG_AUDITOR_FINAL_SCAN_RESULT for item {f_idx} ('{f_detail_update.get('filename')}'): {f_detail_update.get('scan_result', 'NO SCAN_RESULT KEY')}")
                
                overall_course_audit_data.append({
                    'course_name': course_name, 'course_url': course_main_url,
                    'pages_crawled_in_course': crawled_count_this_course,
                    'link_and_file_counts': counts_this_course,
                    'downloaded_files_details': downloaded_for_this_course_details,
                    'external_links_raw_details': external_links_raw_details_this_course
                })
                if gui_stop_event and gui_stop_event.is_set(): break

        if gui_stop_event and gui_stop_event.is_set():
            _log_message_auditor("AUDIT_PROCESS: Audit stopped by user before final report generation.")
        else:
            _log_message_auditor("\nAUDIT_PROCESS: --- Generating Final Audit Summary Report (CSV) ---")
            reports_dir_name = getattr(app_settings, 'REPORTS_SUBDIR', 'audit_reports')
            reports_dir = os.path.join(os.path.abspath(app_settings.MAIN_OUTPUT_DIRECTORY), reports_dir_name)
            os.makedirs(reports_dir, exist_ok=True)
            run_id_str = os.path.basename(app_settings.MAIN_OUTPUT_DIRECTORY).replace("audit_run_", "") if app_settings.MAIN_OUTPUT_DIRECTORY else datetime.now().strftime("%Y%m%d_%H%M%S")
            summary_report_path = os.path.join(reports_dir, f"CourseLinkAudit_Summary_{run_id_str}.csv")

            if overall_course_audit_data:
                generate_course_audit_summary_csv(overall_course_audit_data, summary_report_path)
                url_security_results_map = {}
                any_security_scan_enabled = (
                    (app_settings.ENABLE_VIRUSTOTAL_CHECKS and app_settings.VIRUSTOTAL_API_KEY and "YOUR_ACTUAL" not in app_settings.VIRUSTOTAL_API_KEY) or
                    (app_settings.ENABLE_GOOGLE_SAFE_BROWSING_CHECKS and app_settings.GOOGLE_SAFE_BROWSING_API_KEY and "YOUR_GOOGLE" not in app_settings.GOOGLE_SAFE_BROWSING_API_KEY) or
                    (app_settings.ENABLE_METADEFENDER_CHECKS and app_settings.METADEFENDER_API_KEY and "YOUR_METADEFENDER" not in app_settings.METADEFENDER_API_KEY)
                )
                if any_security_scan_enabled:
                    _log_message_auditor("\nAUDIT_PROCESS: --- Performing Comprehensive URL Security Checks ---")
                    all_external_urls_to_scan = set()
                    for c_summary_data_for_sec_scan in overall_course_audit_data:
                        if gui_stop_event and gui_stop_event.is_set(): break
                        for ext_link_item in c_summary_data_for_sec_scan.get('external_links_raw_details', []):
                            all_external_urls_to_scan.add(ext_link_item['url'])
                    _log_message_auditor(f"AUDIT_PROCESS: Found {len(all_external_urls_to_scan)} unique external URLs for security scanning.")
                    if not (gui_stop_event and gui_stop_event.is_set()):
                        for i_sec, url_to_scan_comprehensively in enumerate(list(all_external_urls_to_scan)):
                            if gui_stop_event and gui_stop_event.is_set(): _log_message_auditor("AUDIT_PROCESS: Stop signal during comprehensive security checks."); break
                            _log_message_auditor(f"AUDIT_PROCESS:   Comprehensive Check ({i_sec+1}/{len(all_external_urls_to_scan)}): {url_to_scan_comprehensively[:70]}...")
                            list_of_results_for_url = get_comprehensive_url_reputation(url_to_scan_comprehensively)
                            url_security_results_map[url_to_scan_comprehensively] = list_of_results_for_url
                    if not (gui_stop_event and gui_stop_event.is_set()):
                        security_json_path = os.path.join(reports_dir, f"URL_Security_Results_ALL_{run_id_str}.json")
                        save_data_to_json_file(url_security_results_map, security_json_path)
                        _log_message_auditor("AUDIT_PROCESS: --- Comprehensive URL Security Checks Complete ---")
                else: 
                    _log_message_auditor("AUDIT_PROCESS: All URL security checks skipped (none enabled or no valid API keys found).")

                if gui_stop_event and gui_stop_event.is_set(): _log_message_auditor("AUDIT_PROCESS: Stopped before detailed HTML reports.")
                else:
                    _log_message_auditor("\nAUDIT_PROCESS: --- Generating Detailed HTML Reports & Main Index ---")
                    course_html_reports_subdir_name = getattr(app_settings, 'COURSE_HTML_REPORTS_SUBDIR_NAME', 'detailed_course_reports')
                    course_html_output_dir = os.path.join(reports_dir, course_html_reports_subdir_name)
                    os.makedirs(course_html_output_dir, exist_ok=True)
                    current_auditor_script_dir = os.path.dirname(os.path.abspath(__file__))
                    report_template_dir = os.path.join(current_auditor_script_dir, "report_templates")

                    if not os.path.isdir(report_template_dir):
                        _log_message_auditor(f"AUDIT_PROCESS_CRITICAL_ERROR: Report template directory not found: {report_template_dir}")
                    else:
                        main_index_course_links_summary = []
                        default_single_security_entry = {
                            "status": "Not Scanned (System)", "positives": 0, "total_scans": 0,
                            "details_link": "#", "last_analysis_date": "N/A", "source": "System"
                        }
                        for course_summary_item_html in overall_course_audit_data:
                            if gui_stop_event and gui_stop_event.is_set(): break
                            course_html_report_input_data = {
                                'course_name': course_summary_item_html.get('course_name'),
                                'course_url': course_summary_item_html.get('course_url'),
                                'pages_crawled_in_course': course_summary_item_html.get('pages_crawled_in_course'),
                                'external_links': [],
                                'downloaded_materials': course_summary_item_html.get('downloaded_files_details', []),
                                'security_analysis': []
                            }
                            processed_urls_for_detailed_table = {} 
                            raw_external_links_for_this_course = course_summary_item_html.get('external_links_raw_details', [])
                            for ext_link_raw_item in raw_external_links_for_this_course:
                                if gui_stop_event and gui_stop_event.is_set(): break
                                ext_url_html = ext_link_raw_item['url']
                                if ext_url_html not in processed_urls_for_detailed_table:
                                    metadata = ref_manager.extract_metadata(ext_url_html)
                                    citation = ref_manager.format_apa7_reference(metadata)
                                    paywall = is_likely_paywall(ext_url_html)
                                    security_results_list_for_url = url_security_results_map.get(ext_url_html, [default_single_security_entry.copy()])
                                    processed_urls_for_detailed_table[ext_url_html] = {
                                        'url': ext_url_html, 'type': ext_link_raw_item.get('type'),
                                        'text': ext_link_raw_item.get('text'), 'source_page_url': ext_link_raw_item.get('source_page_url'),
                                        'is_paywall': paywall, 'reference_citation': citation,
                                        'security_results': security_results_list_for_url 
                                    }
                            if gui_stop_event and gui_stop_event.is_set(): break
                            course_html_report_input_data['external_links'] = list(processed_urls_for_detailed_table.values())
                            unique_external_urls_in_this_course = set(processed_urls_for_detailed_table.keys())
                            for unique_ext_url_for_summary in unique_external_urls_in_this_course:
                                if gui_stop_event and gui_stop_event.is_set(): break
                                all_scan_results_for_this_url = url_security_results_map.get(unique_ext_url_for_summary, [default_single_security_entry.copy()])
                                highest_priority_status_val = "Not Scanned"; status_source = "System"
                                num_positives_summary = 0; num_total_scans_summary = 0
                                details_links_html_parts = []; sources_checked_list = []
                                for res_item in all_scan_results_for_this_url:
                                    current_status_str = res_item.get('status', 'Not Scanned').lower()
                                    current_source = res_item.get('source', 'Unknown'); sources_checked_list.append(current_source)
                                    num_positives_summary += res_item.get('positives', 0); num_total_scans_summary += res_item.get('total_scans', 0)
                                    if res_item.get('details_link') and res_item.get('details_link') != '#': details_links_html_parts.append(f"<a href='{res_item.get('details_link')}' target='_blank'>{current_source}</a>")
                                    if "malicious" in current_status_str or ("flagged by gsb" in current_status_str) or ("flagged by md" in current_status_str and "clean" not in current_status_str) :
                                        highest_priority_status_val = res_item.get('status'); status_source = current_source
                                    elif "error" in current_status_str and "skipped" not in current_status_str :
                                        if not ("malicious" in highest_priority_status_val.lower() or "flagged" in highest_priority_status_val.lower()): highest_priority_status_val = res_item.get('status'); status_source = current_source
                                    elif "clean" in current_status_str:
                                        if "not scanned" in highest_priority_status_val.lower() or "skipped" in highest_priority_status_val.lower(): highest_priority_status_val = res_item.get('status'); status_source = current_source
                                course_html_report_input_data['security_analysis'].append({
                                    'url': unique_ext_url_for_summary, 'overall_status': f"{highest_priority_status_val} (from {status_source})",
                                    'sources_checked': ", ".join(list(set(sources_checked_list))) or "N/A",
                                    'details_links_html': " | ".join(details_links_html_parts) if details_links_html_parts else "N/A",
                                    'total_reported_positives': num_positives_summary, 'total_reported_scans': num_total_scans_summary,
                                    'raw_results_list': all_scan_results_for_this_url
                                })
                            if gui_stop_event and gui_stop_event.is_set(): break
                            
                            _log_message_auditor(f"DEBUG_AUDITOR_INDEX: Generating detailed report for '{course_summary_item_html.get('course_name')}'.")
                            gen_rep_fname = generate_detailed_course_report(course_html_report_input_data, course_html_output_dir, report_template_dir)
                            if gen_rep_fname:
                                _log_message_auditor(f"DEBUG_AUDITOR_INDEX: Detailed report '{gen_rep_fname}' generated. Adding to main index summary.")
                                rel_rep_path = os.path.join(course_html_reports_subdir_name, gen_rep_fname).replace(os.sep, '/')
                                count_of_unique_external_urls_for_summary = len(unique_external_urls_in_this_course)
                                main_index_course_links_summary.append({
                                    'name': course_summary_item_html['course_name'], 'url': course_summary_item_html['course_url'],
                                    'report_path': rel_rep_path, 'pages_crawled': course_summary_item_html.get('pages_crawled_in_course'),
                                    'external_links_count': count_of_unique_external_urls_for_summary,
                                    'downloads_count': len([d for d in course_summary_item_html.get('downloaded_files_details', []) if d.get('success')])
                                })
                            else:
                                _log_message_auditor(f"DEBUG_AUDITOR_INDEX: Detailed report generation FAILED for course '{course_summary_item_html.get('course_name')}'. Not adding to main index.")
                        
                        _log_message_auditor(f"DEBUG_AUDITOR_INDEX: Final main_index_course_links_summary contains {len(main_index_course_links_summary)} items.")
                        if not main_index_course_links_summary and overall_course_audit_data:
                            _log_message_auditor("DEBUG_AUDITOR_INDEX: WARNING - overall_course_audit_data is NOT empty, but main_index_course_links_summary IS empty. Check detailed report generation.")

                        if not (gui_stop_event and gui_stop_event.is_set()):
                            generate_main_index_html(main_index_course_links_summary, reports_dir, report_template_dir, run_id_str)

                full_audit_details_json_path = os.path.join(reports_dir, f"FullAuditData_{run_id_str}.json")
                save_data_to_json_file(overall_course_audit_data, full_audit_details_json_path)
            else: _log_message_auditor("AUDIT_PROCESS: No course data collected to generate reports.")

        if gui_stop_event and gui_stop_event.is_set():
            _log_message_auditor("AUDIT_PROCESS: Audit process was stopped by user.")
        else:
            if app_settings.MAIN_OUTPUT_DIRECTORY: _log_message_auditor(f"\nAUDIT_PROCESS: Audit finished. Outputs in '{app_settings.MAIN_OUTPUT_DIRECTORY}'.")
            else: _log_message_auditor("\nAUDIT_PROCESS: Audit finished. MAIN_OUTPUT_DIRECTORY not set.")

    except Exception as e_main:
        _log_message_auditor(f"AUDIT_PROCESS_CRITICAL_ERROR: {e_main}\n{traceback.format_exc()}")
    finally:
        if driver is not None:
            _log_message_auditor("AUDIT_PROCESS: Closing WebDriver.")
            driver.quit()
        if gui_continue_event: gui_continue_event.clear()
        if gui_stop_event: gui_stop_event.clear()