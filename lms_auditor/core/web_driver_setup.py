# selenium_utils.py
import os
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from lms_auditor.config import app_settings as config 

def initialize_driver():
    print(f"Initializing WebDriver. Driver path: '{config.driver_path}'")
    driver = None
    try:
        # --- CHOOSE YOUR BROWSER ---
        # For Chrome (default):
        service_chrome = webdriver.chrome.service.Service(executable_path=config.driver_path)
        options_chrome = webdriver.ChromeOptions()
        browser_name = "Chrome"

        # For Firefox (uncomment and comment out Chrome lines if using geckodriver in config.py):
        # if "gecko" in config.driver_path.lower():
        #     service_firefox = webdriver.firefox.service.Service(executable_path=config.driver_path)
        #     options_firefox = webdriver.FirefoxOptions()
        #     browser_name = "Firefox"
        # else: # Default to Chrome if not geckodriver
        service = service_chrome
        options = options_chrome


        # options.add_argument("--headless")
        # options.add_argument("--disable-gpu")
        # options.add_argument("--window-size=1920,1080")
        # options.add_argument("--no-sandbox")
        # options.add_argument("--disable-dev-shm-usage")

        # config.MAIN_OUTPUT_DIRECTORY is updated by main_auditor.py to be the timestamped path
        abs_selenium_dl_path = os.path.abspath(os.path.join(config.MAIN_OUTPUT_DIRECTORY, config.SELENIUM_BROWSER_DL_SUBDIR))
        os.makedirs(abs_selenium_dl_path, exist_ok=True)

        if isinstance(options, webdriver.ChromeOptions):
            prefs = {"download.default_directory": abs_selenium_dl_path,
                     "download.prompt_for_download": False,
                     "download.directory_upgrade": True,
                     "safebrowsing.enabled": True}
            options.add_experimental_option("prefs", prefs)
            driver = webdriver.Chrome(service=service, options=options)
        elif isinstance(options, webdriver.FirefoxOptions): # This branch won't be hit if Chrome is default above
            options.set_preference("browser.download.folderList", 2)
            options.set_preference("browser.download.manager.showWhenStarting", False)
            options.set_preference("browser.download.dir", abs_selenium_dl_path)
            mime_types = (
                "application/octet-stream,application/pdf,application/zip,application/msword,"
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document,"
                "application/vnd.ms-powerpoint,application/vnd.openxmlformats-officedocument.presentationml.presentation,"
                "application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet,"
                "text/plain,text/csv,image/jpeg,image/png,image/gif,audio/mpeg,video/mp4,video/quicktime"
            ) # Expanded MIME types
            options.set_preference("browser.helperApps.neverAsk.saveToDisk", mime_types)
            driver = webdriver.Firefox(service=service, options=options)
        else: # Should not happen if using Chrome or Firefox options explicitly
            raise WebDriverException("Browser options not recognized for Chrome or Firefox.")

        print(f"WebDriver initialized ({browser_name}). Downloads set to: {abs_selenium_dl_path}")
        return driver
    except WebDriverException as e_wd:
        print(f"CRITICAL ERROR initializing WebDriver: {e_wd}\n"
              f"Ensure 'driver_path' in config.py ('{config.driver_path}') is correct, compatible, and executable.")
        return None
    except Exception as e_wd_other:
        print(f"CRITICAL UNEXPECTED ERROR initializing WebDriver: {e_wd_other}")
        import traceback
        traceback.print_exc()
        return None

def get_cookies_for_requests_from_driver(driver):
    """
    Retrieves cookies from the Selenium WebDriver and formats them
    as a dictionary suitable for the `requests` library's `cookies` parameter.
    """
    if driver is None:
        print("WARNING: WebDriver instance is None in get_cookies_for_requests_from_driver.")
        return None

    try:
        selenium_cookies = driver.get_cookies() # This returns a list of cookie dictionaries
    except Exception as e:
        print(f"ERROR: Failed to get cookies from driver: {e}")
        return None # Return None on error

    if not selenium_cookies:
        return None # No cookies found

    # Convert the list of Selenium cookie dictionaries into a simple
    # name:value dictionary for the 'requests' library.
    cookies_dict = {}
    for cookie in selenium_cookies:
        if 'name' in cookie and 'value' in cookie:
            cookies_dict[cookie['name']] = cookie['value']
        else:
            # This shouldn't happen with valid Selenium cookies, but good to be aware
            print(f"WARNING: Encountered malformed cookie: {cookie}")

    if not cookies_dict: # If all cookies were malformed or list was empty after filtering
        return None

    return cookies_dict