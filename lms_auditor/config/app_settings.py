# app_settings.py
import sys
import os

def _get_driver_path_for_bundle():
    """Determines the path for chromedriver when bundled."""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, 'chromedriver.exe')
    elif getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
        return os.path.join(application_path, 'chromedriver.exe')
    else:
        current_dir = os.path.dirname(os.path.abspath(__file__)) 
        project_root_approx = os.path.dirname(os.path.dirname(current_dir)) 
        return os.path.join(project_root_approx, "chromedriver.exe")
driver_path = _get_driver_path_for_bundle()

# --- Moodle & Target URLs ---
MOODLE_LOGIN_URL = "https://moodleprod.murdoch.edu.au"
MOODLE_DASHBOARD_URL = "https://moodleprod.murdoch.edu.au/my/" # <<< VERIFY THIS URL!

# --- Directories for Output (base names) ---
MAIN_OUTPUT_DIRECTORY_BASE = "lms_audit_runs_final"
# MAIN_OUTPUT_DIRECTORY will be dynamically set by the main script for each run
HTML_SUBDIR = "html_pages_per_course"
FILES_SUBDIR = "downloaded_course_files"
REPORTS_SUBDIR = "audit_reports" # This is used by main_auditor.py
COURSE_HTML_REPORTS_SUBDIR_NAME = "detailed_course_reports" # This is used by main_auditor.py and app_gui.py
SELENIUM_BROWSER_DL_SUBDIR = "selenium_browser_autodownloads"

# --- Domain Config ---
LMS_SPECIFIC_DOMAIN = "moodleprod.murdoch.edu.au" # <<< VERIFY / UPDATE
UNIVERSITY_ROOT_DOMAIN = "murdoch.edu.au" # <<< VERIFY / UPDATE

# --- Crawler Config for WITHIN each course ---
INTERNAL_COURSE_PAGE_PATTERNS = [
    '/mod/resource/view.php', '/mod/page/view.php', '/mod/folder/view.php',
    '/mod/forum/view.php', '/mod/quiz/view.php', '/mod/assign/view.php',
    '/mod/lesson/view.php', '/mod/book/view.php', '/mod/url/view.php',
    '/mod/teammeeting/view.php', '/course/view.php',
]
DOWNLOADABLE_EXTENSIONS = [
    '.pdf', '.doc', '.docx', '.ppt', '.pptx', '.xls', '.xlsx', '.zip', '.rar', '.7z',
    '.txt', '.csv', '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.mov', '.avi',
    '.webm', '.odt', '.odp', '.ods', '.rtf', '.pages', '.key', '.numbers', '.m3u8'
]
MAX_PAGES_TO_CRAWL_PER_COURSE = 1 # GUI will override this

# --- API Config ---
ENABLE_VIRUSTOTAL_CHECKS = False # GUI will override this
VIRUSTOTAL_API_KEY = "YOUR_ACTUAL_VIRUSTOTAL_API_KEY_HERE" # GUI will override this

### NEW: Google Safe Browsing API Config ###
ENABLE_GOOGLE_SAFE_BROWSING_CHECKS = False # GUI will override this
GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_GOOGLE_KEY_SHOULD_END_HERE_NO_NEWLINE" # GUI will override this
GOOGLE_SAFE_BROWSING_API_URL = "https://webrisk.googleapis.com/v1/uris:search" # Web Risk API endpoint

### NEW: Metadefender Cloud API Config ###
ENABLE_METADEFENDER_CHECKS = False # GUI will override this
METADEFENDER_API_KEY = "YOUR_METADEFENDER_API_KEY_HERE" # GUI will override this
METADEFENDER_URL_INFO_API_URL = "https://api.metadefender.com/v4/url/" # For cached results by URL hash
METADEFENDER_URL_SCAN_API_URL = "https://api.metadefender.com/v4/url" # For submitting a new URL to scan

# --- Local Scan Config ---
ENABLE_LOCAL_FILE_SCANS = False # GUI will override this
LOCAL_AV_SCANNER_COMMAND = "clamscan" # Default, GUI can allow setting a full path
CLAMAV_WINDOWS_DOWNLOAD_URL = "https://www.clamav.net/downloads/production/clamav-1.4.2.win.win32.msi" # MODIFIED: More general download page

USER_AGENT_FOR_REQUESTS = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 LMSAuditBot/1.0"

# This will be updated by main_auditor.py at runtime to the timestamped path
MAIN_OUTPUT_DIRECTORY = ""

# Add configurations for academic referencing
REFERENCE_STYLE = "APA7"
CONTENT_WARNING_MESSAGE = """
This link leads to third-party content which may require subscription/payment.
Original source: {url}
Access date: {access_date}
"""

# Add paywall detection patterns
PAYWALL_INDICATORS = [
    "subscribe", "subscription", "sign up", "premium", "register",
    "payment required", "paid content", "members only", "institutional login",
    "access options", "get access", "view options"
]

# For fetching HTML of external links for metadata/paywall checks. Can be slow.
FETCH_EXTERNAL_LINK_HTML = False # GUI will override this
EXTERNAL_LINK_HTML_FETCH_TIMEOUT = 2 # GUI will override this

#Quick Grab
ENABLE_QUICK_GRAB_CONTENT_PAGES = False

# Add reference metadata fields (primarily for documentation, not direct use by simple extractors)
REFERENCE_METADATA_FIELDS = [
    'title', 'authors', 'publication_date', 'doi',
    'journal', 'publisher', 'access_date'
]

# REPORTS_SUBDIR and COURSE_HTML_REPORTS_SUBDIR_NAME were duplicated at the end, removed the duplicates.

SELENIUM_DEFAULT_FULL_LOAD_WAIT = 7 # Default wait for non-dashboard full loads
SELENIUM_DASHBOARD_WAIT_SECONDS = 20
MOODLE_DASHBOARD_COURSE_LIST_LOADED_SELECTOR = None # Example, **CHANGE THIS**
COURSE_NAME_SELECTORS = [ # Default selectors for course names
    'header#page-header h1',
    'div.page-header-headings h1',
    'h1[data-region="course-title"]',
    '.h2.font-weight-bold[data-region="course-title"]',
    # 'div.coursename a', # Often too broad or picks up parent course in breadcrumbs
    'h1.title',
    'span.breadcrumb-item.active span[aria-current="page"]'
]
MAX_FILENAME_LENGTH = 200