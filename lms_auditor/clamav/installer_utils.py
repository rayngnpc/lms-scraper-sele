# lms_auditor/clamav/installer_utils.py
import os
import requests
from urllib.parse import urlparse
import traceback
# config will be passed or specific values from it will be passed
# from lms_auditor.config import app_settings # Or pass required config values

# This function is a thread target, it should communicate progress via a queue.
# It should not directly interact with GUI elements.
def download_clamav_installer_thread_target(url, download_q_local, user_agent, temp_dir_override=None):
    clamav_installer_path_thread_local = None # Use a local var for the path within the thread
    try:
        temp_dir = temp_dir_override if temp_dir_override else os.environ.get("TEMP", os.getcwd())
        parsed_url = urlparse(url)
        filename = os.path.basename(parsed_url.path)
        if not filename or not filename.lower().endswith((".msi", ".exe")):
            filename = "clamav_installer.msi"

        clamav_installer_path_thread_local = os.path.join(temp_dir, filename)
        download_q_local.put(("progress_text", f"Connecting to download {filename}...", None))

        headers = {'User-Agent': user_agent}
        response = requests.get(url, stream=True, timeout=120, headers=headers)
        response.raise_for_status()

        raw_total_size = response.headers.get('content-length')
        total_size = 0
        if raw_total_size:
            try: total_size = int(raw_total_size)
            except ValueError: total_size = 0

        if total_size > 0:
            download_q_local.put(("total_size", total_size, None))
        else:
            download_q_local.put(("total_size", None, None))

        download_q_local.put(("progress_text", f"Starting download of {filename} to {temp_dir}...", None))

        bytes_downloaded = 0
        chunk_size_dl = 1024 * 256

        with open(clamav_installer_path_thread_local, 'wb') as file_handle:
            for chunk in response.iter_content(chunk_size=chunk_size_dl):
                if chunk:
                    file_handle.write(chunk)
                    bytes_downloaded += len(chunk)
                    if total_size > 0:
                        progress_percent = (bytes_downloaded / total_size) * 100.0
                        download_q_local.put(("progress_update",
                                              f"Downloading... {bytes_downloaded // (1024*1024)}MB / {total_size // (1024*1024)}MB ({progress_percent:.1f}%)\n",
                                              progress_percent))
                    else:
                        download_q_local.put(("progress_update",
                                              f"Downloading... {bytes_downloaded // (1024*1024)}MB (size unknown)\n",
                                              -1.0))

        download_q_local.put(("complete", "Download complete.\n", clamav_installer_path_thread_local))

    except requests.exceptions.RequestException as e_req:
        download_q_local.put(("error", f"Download failed: {e_req}\n", None))
        # clamav_installer_path_thread_local remains None or its previous value
    except Exception as e_gen:
        download_q_local.put(("error", f"An unexpected error occurred during download: {e_gen}\n{traceback.format_exc()}", None))
    # The function implicitly returns None, the path is sent via queue.