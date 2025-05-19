# lms_auditor/gui/clamav_gui_manager.py
import tkinter as tk
from tkinter import ttk, messagebox # filedialog not directly used here
import os
import sys
import platform
import threading
import queue
import tempfile
import time
import webbrowser
from urllib.parse import urlparse
import traceback

from lms_auditor.config import app_settings
from lms_auditor.clamav.scanner_control import (
    find_clamscan_executable_internal,
    scan_file_locally,
    find_freshclam_executable
)
from lms_auditor.clamav.installer_utils import download_clamav_installer_thread_target
from lms_auditor.utils.system_ops import run_elevated_windows_executable
from .ui_helpers import COLOR_FRAME_BG # For theming dialogs if needed

try:
    _current_dir = os.path.dirname(os.path.abspath(__file__)) # lms_auditor/gui
    _lms_auditor_root_dir = os.path.dirname(_current_dir)     # lms_auditor
    CONFIGURE_CLAMAV_SCRIPT_PATH = os.path.join(_lms_auditor_root_dir, "clamav", "config_tool_script.py")
except NameError:
    CONFIGURE_CLAMAV_SCRIPT_PATH = "lms_auditor/clamav/config_tool_script.py" # Fallback

# Module-level state (careful with these in multi-instance scenarios, but fine for single GUI)
is_handling_local_scan_toggle = False
clamav_installer_path_global = None


def check_clamav_download_progress(root_window, progress_dialog, progress_label, progress_bar, download_q_local, download_thread, log_q, post_download_callback):
    # root_window: main tk root
    # post_download_callback: typically handle_clamav_post_download
    try:
        msg_type, msg_data, val = download_q_local.get_nowait()

        if isinstance(msg_data, str) and msg_type != "error":
            if log_q: log_q.put(msg_data)

        if msg_type == "total_size":
            # ... (same logic as in original app_gui.py)
            current_total_size = msg_data
            if current_total_size is not None and current_total_size > 0:
                progress_bar.config(mode='determinate', maximum=100, value=0)
            else:
                progress_bar.config(mode='indeterminate')
                progress_bar.start(10)
        elif msg_type == "progress_text":
             if isinstance(msg_data, str):
                 progress_label.config(text=msg_data.strip().splitlines()[-1])
        elif msg_type == "progress_update":
            if isinstance(msg_data, str):
                 progress_label.config(text=msg_data.strip().splitlines()[-1])
            if isinstance(val, (float, int)) and val >= 0 and progress_bar['mode'] == 'determinate':
                progress_bar['value'] = val
        elif msg_type == "complete":
            progress_label.config(text="Download complete!")
            progress_bar.stop()
            if progress_bar['mode'] == 'determinate': progress_bar['value'] = 100
            if progress_dialog.winfo_exists(): progress_dialog.destroy()
            post_download_callback(True, val) # val is installer_path
            return
        elif msg_type == "error":
            progress_label.config(text="Download failed!")
            progress_bar.stop()
            if progress_dialog.winfo_exists(): progress_dialog.destroy()
            messagebox.showerror("Download Error", msg_data if isinstance(msg_data, str) else "An unknown download error occurred.")
            post_download_callback(False, None)
            return
    except queue.Empty:
        if not download_thread.is_alive() and download_q_local.empty():
            if log_q: log_q.put("WARN_CLAMAV_GUI: Download thread ended unexpectedly.\n")
            if progress_dialog.winfo_exists(): progress_dialog.destroy()
            post_download_callback(False, None)
            return
    except Exception as e_progress_check:
        if log_q: log_q.put(f"ERROR_CLAMAV_GUI: Error in check_clamav_download_progress: {e_progress_check}\n{traceback.format_exc()}\n")
        if progress_dialog.winfo_exists(): progress_dialog.destroy()
        post_download_callback(False, None)
        return

    if progress_dialog.winfo_exists():
        root_window.after(100, lambda: check_clamav_download_progress(root_window, progress_dialog, progress_label, progress_bar, download_q_local, download_thread, log_q, post_download_callback))

def handle_freshclam_request_from_gui(log_q): # Needs log_q
    if platform.system() != "Windows":
        messagebox.showinfo("ClamAV Databases", "ClamAV database issues detected. On non-Windows systems, please try running 'sudo freshclam' or your system's equivalent command to update the virus definitions.")
        return

    response = messagebox.askyesno(
        "ClamAV Database Update",
        "ClamAV reported errors loading its virus databases (e.g., they might be missing or outdated).\n\n"
        "Would you like to attempt to run freshclam.exe now to update them?\n"
        "(This will require Administrator privileges via a UAC prompt)."
    )
    if response:
        freshclam_exe_path = find_freshclam_executable() # From scanner_control
        if freshclam_exe_path:
            if log_q: log_q.put(f"INFO_CLAMAV_GUI: Found freshclam.exe at: {freshclam_exe_path}\n")
            # Use system_ops.run_elevated_windows_executable
            success_launch, msg_launch = run_elevated_windows_executable(freshclam_exe_path, log_q=log_q)
            if success_launch:
                messagebox.showinfo(
                    "Running freshclam.exe - ACTION REQUIRED",
                    f"{msg_launch}\n\n"
                    "IMPORTANT:\n"
                    "1. Approve the UAC prompt if it appears for 'freshclam.exe'.\n"
                    "2. A console window for freshclam.exe will open. **Wait for this window to complete its operations and close automatically.**\n"
                    "3. After the freshclam console has closed, click 'OK' on THIS dialog.\n\n"
                    "You may then need to re-run or re-enable local scans if issues persist."
                )
            else:
                messagebox.showerror("Error Launching freshclam.exe", msg_launch)
        else:
            messagebox.showerror(
                "freshclam.exe Not Found",
                "Could not automatically find freshclam.exe. Please ensure ClamAV is correctly installed and its installation directory (containing freshclam.exe) is in your system's PATH, or update the databases manually using the ClamAV tools."
            )
    else:
        messagebox.showwarning(
            "Database Update Skipped",
            "You chose not to update the ClamAV databases. Local file scans may fail or report errors until the databases are up-to-date."
        )

def attempt_automatic_clamav_config_fix(log_q): # Needs log_q
    if platform.system() != "Windows":
        if log_q: log_q.put("INFO_CLAMAV_GUI: ClamAV config fix script is Windows-specific. Skipping on non-Windows.\n")
        return False

    if not os.path.exists(CONFIGURE_CLAMAV_SCRIPT_PATH):
        if log_q: log_q.put(f"ERROR_CLAMAV_GUI: ClamAV configuration helper script not found: {CONFIGURE_CLAMAV_SCRIPT_PATH}\n")
        messagebox.showerror("Helper Script Missing", f"The ClamAV configuration helper script is missing.\nExpected at: {CONFIGURE_CLAMAV_SCRIPT_PATH}")
        return False

    if log_q: log_q.put("INFO_CLAMAV_GUI: Attempting to run ClamAV configuration fixer script with elevation...\n")
    python_exe = sys.executable
    parameters_for_script = f'"{CONFIGURE_CLAMAV_SCRIPT_PATH}"'
    success_launch, msg_launch = run_elevated_windows_executable(python_exe, parameters_for_script, log_q=log_q) # Pass log_q

    if success_launch:
        messagebox.showinfo(
            "ClamAV Configuration Fixer - ACTION REQUIRED",
            f"{msg_launch}\n\n"
            "IMPORTANT:\n"
            "1. If a UAC prompt appears for 'Python', please approve it.\n"
            "2. **A small window or console MAY appear briefly. Wait for it to complete and disappear.**\n"
            "3. Only after the script has finished, click 'OK' on THIS dialog.\n\n"
            "The application will re-test ClamAV's status."
        )
        if log_q: log_q.put("INFO_CLAMAV_GUI: User acknowledged ClamAV configuration fixer script run.\n")
        return True
    else:
        messagebox.showerror("Configuration Fixer Launch Error", f"Could not launch ClamAV config fixer script:\n{msg_launch}")
        return False

def check_and_update_clamav_databases(log_q, var_ls_ref, finalize_callback_success, finalize_callback_failure): # Needs log_q, var_ls_ref
    # var_ls_ref is the tk.BooleanVar for the local scan checkbox
    # finalize_callback_success/failure are callables to update checkbox and state
    if log_q: log_q.put("INFO_CLAMAV_GUI: Proactively checking ClamAV database status & configuration...\n")
    dummy_file_path = ""
    try:
        temp_dir = tempfile.gettempdir()
        dummy_file_path = os.path.join(temp_dir, f"clamav_lmsauditor_test_scan_{int(time.time())}.txt")
        with open(dummy_file_path, "w") as tmp_file:
            tmp_file.write("Harmless test file for ClamAV check by LMS Auditor.\n")
        if log_q: log_q.put(f"INFO_CLAMAV_GUI: Created dummy file: {dummy_file_path}\n")

        # Pass log_q to scan_file_locally if it accepts it, or ensure its own log_queue is set
        # For now, assuming scan_file_locally in scanner_control uses its own log_queue or prints
        test_scan_result = scan_file_locally(dummy_file_path, force_scan_for_test=True) # scanner_control.log_queue used here
        if log_q: log_q.put(f"INFO_CLAMAV_GUI: Initial test scan result: {test_scan_result}\n")
        needs_db_update_explicitly = test_scan_result.get("needs_freshclam", False)
        is_test_scan_ok = test_scan_result.get("status") == "Clean"
        is_test_scan_critically_failed = test_scan_result.get("status") in [
            "LocalScanDisabled", "FileNotFoundForScan", "ScannerNotFoundAtScanTime",
            "FileNotFoundAtScanCommand", "InvalidScannerPath"
        ]

        if is_test_scan_ok and not needs_db_update_explicitly:
            if log_q: log_q.put("INFO_CLAMAV_GUI: ClamAV databases appear loaded and test file scanned successfully (Clean).\n")
            messagebox.showinfo("ClamAV Database Check", "ClamAV databases loaded correctly and a test scan was successful.")
            finalize_callback_success()
            return

        if is_test_scan_critically_failed:
             if log_q: log_q.put(f"WARN_CLAMAV_GUI: Critical failure during ClamAV test scan: {test_scan_result.get('status')} - Details: {test_scan_result.get('details')}\n")
             messagebox.showerror("ClamAV Test Scan Failed", f"A critical error occurred during the ClamAV test scan: {test_scan_result.get('status')}\nDetails: {test_scan_result.get('details')}")
             finalize_callback_failure()
             return

        if platform.system() != "Windows":
            messagebox.showwarning("ClamAV Issue Detected", "A ClamAV issue was detected. On non-Windows systems, please run 'sudo freshclam' or equivalent.")
            finalize_callback_failure(); return

        config_fix_attempted = False
        if needs_db_update_explicitly or test_scan_result.get("status") == "ScanError":
            response_fix_conf = messagebox.askyesno(
                "ClamAV Configuration Check",
                "ClamAV reported issues. This might be due to incorrect configuration files.\n\n"
                "Attempt an automatic fix for common ClamAV configuration problems?"
            )
            if response_fix_conf:
                config_fix_attempted = attempt_automatic_clamav_config_fix(log_q)
                if config_fix_attempted:
                    if log_q: log_q.put("INFO_CLAMAV_GUI: Re-testing ClamAV scan status after configuration fix attempt...\n")
                    test_scan_after_conf_fix = scan_file_locally(dummy_file_path, force_scan_for_test=True)
                    if log_q: log_q.put(f"INFO_CLAMAV_GUI: Test scan after config fix: {test_scan_after_conf_fix}\n")

                    needs_db_update_flag_after_conf = test_scan_after_conf_fix.get("needs_freshclam", False)
                    is_test_scan_ok_after_conf = test_scan_after_conf_fix.get("status") == "Clean"

                    if is_test_scan_ok_after_conf and not needs_db_update_flag_after_conf:
                         if log_q: log_q.put("INFO_CLAMAV_GUI: ClamAV configuration fix attempt resolved issues.\n")
                         messagebox.showinfo("Configuration Fix Successful", "ClamAV configuration and databases seem correct now.")
                         finalize_callback_success()
                         return
                    else:
                         if log_q: log_q.put("WARN_CLAMAV_GUI: ClamAV issues persist after configuration fix attempt.\n")
                         needs_db_update_explicitly = needs_db_update_flag_after_conf

        should_offer_freshclam = needs_db_update_explicitly or \
                                (test_scan_result.get("status") == "ScanError" and not (is_test_scan_ok and not needs_db_update_explicitly))

        if should_offer_freshclam:
            response_run_freshclam = messagebox.askyesno("ClamAV Database Update", "ClamAV databases still appear to need an update.\n\nRun freshclam.exe now?")
            if response_run_freshclam:
                freshclam_exe_path = find_freshclam_executable()
                if freshclam_exe_path:
                    success_launch_fc, msg_launch_fc = run_elevated_windows_executable(freshclam_exe_path, log_q=log_q) # Pass log_q
                    if success_launch_fc:
                        messagebox.showinfo(
                            "Running freshclam.exe - ACTION REQUIRED",
                            f"{msg_launch_fc}\n\nIMPORTANT: Wait for 'freshclam.exe' console to finish, then click 'OK'."
                        )
                        if log_q: log_q.put("INFO_CLAMAV_GUI: User acknowledged freshclam.exe run. Re-testing...\n")
                        test_scan_after_freshclam = scan_file_locally(dummy_file_path, force_scan_for_test=True)
                        if log_q: log_q.put(f"INFO_CLAMAV_GUI: Test scan after freshclam: {test_scan_after_freshclam}\n")

                        if test_scan_after_freshclam.get("status") == "Clean" and not test_scan_after_freshclam.get("needs_freshclam", False):
                            messagebox.showinfo("Database Update Successful", "ClamAV databases updated. Test scan successful.")
                            finalize_callback_success()
                        else:
                            messagebox.showwarning("Update Possibly Incomplete", "ClamAV might still have issues after freshclam.")
                            finalize_callback_failure()
                    else:
                        messagebox.showerror("Error Launching freshclam.exe", msg_launch_fc)
                        finalize_callback_failure()
                else:
                    messagebox.showerror("freshclam.exe Not Found", "Could not find freshclam.exe.")
                    finalize_callback_failure()
            else:
                messagebox.showwarning("Database Update Skipped", "You chose not to run freshclam.exe.")
                finalize_callback_failure()
        elif is_test_scan_ok and not needs_db_update_explicitly:
            finalize_callback_success()
        else:
             if log_q: log_q.put(f"WARN_CLAMAV_GUI: ClamAV setup remains incomplete. Final status: {test_scan_result.get('status')}\n")
             messagebox.showwarning("ClamAV Setup Incomplete", f"ClamAV setup could not be fully verified. Last status: '{test_scan_result.get('status')}'")
             finalize_callback_failure()

    except Exception as e_db_check:
        if log_q: log_q.put(f"ERROR_CLAMAV_GUI: Unexpected error during ClamAV check: {e_db_check}\n{traceback.format_exc()}\n")
        messagebox.showerror("ClamAV Check Error", f"Unexpected error during ClamAV check: {e_db_check}")
        finalize_callback_failure()
    finally:
        if dummy_file_path and os.path.exists(dummy_file_path):
            try:
                os.remove(dummy_file_path)
                if log_q: log_q.put(f"INFO_CLAMAV_GUI: Removed dummy test file: {dummy_file_path}\n")
            except Exception as e_remove:
                if log_q: log_q.put(f"WARN_CLAMAV_GUI: Could not remove dummy test file {dummy_file_path}: {e_remove}\n")


def handle_clamav_post_download(root_window, log_q, var_ls_ref, download_successful, installer_path): # Needs root, log_q, var_ls_ref
    global is_handling_local_scan_toggle # This global is specific to this manager's state
                                         # and should be managed carefully.

    def _finalize_toggle_after_all_setup(new_state_bool):
        current_checkbox_state = var_ls_ref.get()
        if current_checkbox_state != new_state_bool:
            if log_q: log_q.put(f"DEBUG_CLAMAV_GUI: Setting local scan checkbox from {current_checkbox_state} to {new_state_bool}.\n")
            var_ls_ref.set(new_state_bool)
        else:
            if log_q: log_q.put(f"DEBUG_CLAMAV_GUI: Local scan checkbox already {new_state_bool}.\n")

        global is_handling_local_scan_toggle # Explicitly modify the module-level global flag
        is_handling_local_scan_toggle = False # Reset here
        if log_q: log_q.put(f"DEBUG_CLAMAV_GUI: Finalized post-download. State: {new_state_bool}. Handling flag reset.\n")


    if not download_successful or not installer_path:
        if log_q: log_q.put("ERROR_CLAMAV_GUI: ClamAV installer download failed. Local scanning disabled.\n")
        _finalize_toggle_after_all_setup(False)
        return

    if log_q: log_q.put(f"INFO_CLAMAV_GUI: ClamAV installer downloaded to: {installer_path}\n")
    user_response_install = messagebox.askyesno(
        "ClamAV Download Complete",
        f"ClamAV installer downloaded to:\n{installer_path}\n\nRun the installer now?"
    )

    if not user_response_install:
        if log_q: log_q.put("INFO_CLAMAV_GUI: User declined to run ClamAV installer. Local scanning disabled.\n")
        messagebox.showinfo("ClamAV Installation Skipped", f"You can manually run installer from:\n{installer_path}")
        _finalize_toggle_after_all_setup(False)
        return

    success_launch_msi, msg_launch_msi = run_elevated_windows_executable(installer_path, log_q=log_q) # Pass log_q
    if not success_launch_msi:
        messagebox.showerror("ClamAV Installation Error", f"Failed to launch ClamAV installer:\n{msg_launch_msi}")
        _finalize_toggle_after_all_setup(False)
        return

    messagebox.showinfo(
        "ClamAV Installation - ACTION REQUIRED",
        f"{msg_launch_msi}\n\nIMPORTANT: Follow installer prompts. After it FINISHES, click 'OK' here."
    )

    if log_q: log_q.put("INFO_CLAMAV_GUI: User confirmed ClamAV MSI installation complete. Re-checking...\n")
    scanner_path_after_msi = find_clamscan_executable_internal()

    if not scanner_path_after_msi:
        if log_q: log_q.put("WARN_CLAMAV_GUI: clamscan.exe still not found after MSI installation.\n")
        messagebox.showwarning("ClamAV Setup Incomplete", "clamscan.exe still not found. Local scanning disabled.")
        _finalize_toggle_after_all_setup(False)
        return

    if log_q: log_q.put(f"INFO_CLAMAV_GUI: ClamAV found at '{scanner_path_after_msi}'. Checking config/databases.\n")
    check_and_update_clamav_databases(
        log_q, var_ls_ref,
        finalize_callback_success=lambda: _finalize_toggle_after_all_setup(True),
        finalize_callback_failure=lambda: _finalize_toggle_after_all_setup(False)
    )


def handle_local_scan_toggle(root_window, log_q, var_ls_ref, *args): # Needs root, log_q, var_ls_ref
    global is_handling_local_scan_toggle, clamav_installer_path_global

    if is_handling_local_scan_toggle:
        if log_q: log_q.put("DEBUG_CLAMAV_GUI: handle_local_scan_toggle re-entered, ignoring.\n")
        return
    is_handling_local_scan_toggle = True
    if log_q: log_q.put("DEBUG_CLAMAV_GUI: Entered handle_local_scan_toggle. Flag set.\n")

    user_intended_state = var_ls_ref.get()

    def _finalize_toggle_main(final_checkbox_state_bool):
        current_checkbox_state = var_ls_ref.get()
        if current_checkbox_state != final_checkbox_state_bool:
            if log_q: log_q.put(f"DEBUG_CLAMAV_GUI: _finalize_toggle_main: Setting checkbox to {final_checkbox_state_bool}.\n")
            var_ls_ref.set(final_checkbox_state_bool)
        else:
            if log_q: log_q.put(f"DEBUG_CLAMAV_GUI: _finalize_toggle_main: Checkbox already {final_checkbox_state_bool}.\n")
        global is_handling_local_scan_toggle
        is_handling_local_scan_toggle = False
        if log_q: log_q.put(f"DEBUG_CLAMAV_GUI: _finalize_toggle_main: Finalized. State: {final_checkbox_state_bool}. Flag reset.\n")

    if not user_intended_state:
        if log_q: log_q.put("INFO_CLAMAV_GUI: Local file scan disabled by user.\n")
        _finalize_toggle_main(False)
        return

    if platform.system() != "Windows":
        if log_q: log_q.put("INFO_CLAMAV_GUI: Local scan enabled (non-Windows). Assuming external ClamAV setup.\n")
        messagebox.showinfo("Local Scan (Non-Windows)", "Local file scanning enabled. Ensure ClamAV is installed and up-to-date.")
        _finalize_toggle_main(True)
        return

    if log_q: log_q.put("INFO_CLAMAV_GUI: User enabled local scan (Windows). Checking ClamAV...\n")
    scanner_path = find_clamscan_executable_internal()

    if scanner_path:
        if log_q: log_q.put(f"INFO_CLAMAV_GUI: ClamAV found: {scanner_path}. Checking databases/config.\n")
        check_and_update_clamav_databases(
            log_q, var_ls_ref,
            finalize_callback_success=lambda: _finalize_toggle_main(True),
            finalize_callback_failure=lambda: _finalize_toggle_main(False)
        )
        return

    if log_q: log_q.put("WARN_CLAMAV_GUI: ClamAV (clamscan.exe) not found. Prompting for installation.\n")
    temp_dir = os.environ.get("TEMP", os.getcwd())
    expected_fn = "clamav_installer.msi" # Default
    if hasattr(app_settings, 'CLAMAV_WINDOWS_DOWNLOAD_URL') and app_settings.CLAMAV_WINDOWS_DOWNLOAD_URL:
        try:
            basename = os.path.basename(urlparse(app_settings.CLAMAV_WINDOWS_DOWNLOAD_URL).path)
            if basename and basename.lower().endswith((".msi", ".exe")): expected_fn = basename
        except Exception: pass
    potential_existing_path = os.path.join(temp_dir, expected_fn)

    if os.path.exists(potential_existing_path) and os.path.getsize(potential_existing_path) > 1024*1024:
        resp_inst_exist = messagebox.askyesno("Existing ClamAV Installer", f"Existing installer found:\n{potential_existing_path}\n\nUse this version?")
        if resp_inst_exist:
            clamav_installer_path_global = potential_existing_path
            # Pass root_window, log_q, var_ls_ref
            handle_clamav_post_download(root_window, log_q, var_ls_ref, True, potential_existing_path)
            return
        resp_dl_anyway = messagebox.askyesno("Download New Installer?", "Not using existing. Download fresh ClamAV installer?")
        if not resp_dl_anyway:
            messagebox.showinfo("ClamAV Setup Skipped", "Installation skipped. Local scanning disabled.")
            _finalize_toggle_main(False); return

    if not hasattr(app_settings, 'CLAMAV_WINDOWS_DOWNLOAD_URL') or not app_settings.CLAMAV_WINDOWS_DOWNLOAD_URL:
        messagebox.showerror("Configuration Error", "ClamAV download URL not configured.")
        _finalize_toggle_main(False); return

    is_direct_link = app_settings.CLAMAV_WINDOWS_DOWNLOAD_URL.lower().endswith((".msi", ".exe"))
    if not is_direct_link:
        resp_page = messagebox.askyesno("ClamAV Download Page", "Configured URL not a direct link. Open download page in browser?")
        if resp_page:
            try: webbrowser.open(app_settings.CLAMAV_WINDOWS_DOWNLOAD_URL)
            except Exception as e_web: messagebox.showerror("Browser Error", f"Could not open browser: {e_web}")
        messagebox.showinfo("Manual Download", "Download ClamAV manually. Then re-enable local scan.")
        _finalize_toggle_main(False); return

    resp_dl_final = messagebox.askyesno("Download ClamAV Installer?", f"Download ClamAV installer from:\n{app_settings.CLAMAV_WINDOWS_DOWNLOAD_URL}?")
    if not resp_dl_final:
        messagebox.showinfo("Download Skipped", "Download skipped. Local scanning disabled.")
        _finalize_toggle_main(False); return

    if log_q: log_q.put(f"INFO_CLAMAV_GUI: Proceeding to download ClamAV installer from {app_settings.CLAMAV_WINDOWS_DOWNLOAD_URL}.\n")
    download_q_local = queue.Queue()
    dl_thread = threading.Thread(
        target=download_clamav_installer_thread_target,
        args=(app_settings.CLAMAV_WINDOWS_DOWNLOAD_URL, download_q_local, app_settings.USER_AGENT_FOR_REQUESTS, temp_dir), # Pass user_agent and temp_dir
        daemon=True
    )

    prog_dialog = tk.Toplevel(root_window)
    prog_dialog.title("Downloading ClamAV Installer")
    prog_dialog.geometry("450x130")
    prog_dialog.resizable(False, False)
    prog_dialog.transient(root_window)
    prog_dialog.grab_set()
    prog_dialog.configure(bg=COLOR_FRAME_BG) # From ui_helpers (or define locally)

    prog_label = ttk.Label(prog_dialog, text="Initiating ClamAV download...", wraplength=430, anchor=tk.W)
    prog_label.pack(pady=(10,5), padx=10, fill=tk.X)
    prog_bar = ttk.Progressbar(prog_dialog, mode='indeterminate', length=430)
    prog_bar.pack(pady=5, padx=10, fill=tk.X)
    prog_bar.start(10)

    def cancel_download_action():
        if log_q: log_q.put("INFO_CLAMAV_GUI: User cancelled ClamAV download via dialog.\n")
        if prog_dialog.winfo_exists(): prog_dialog.destroy()
        _finalize_toggle_main(False) # Assume download is effectively cancelled
    cancel_button = ttk.Button(prog_dialog, text="Cancel", command=cancel_download_action)
    cancel_button.pack(pady=(5,10))

    if root_window: root_window.update_idletasks()
    dl_thread.start()
    # Pass the correct callback for post_download
    post_download_cb_for_checker = lambda success, path: handle_clamav_post_download(root_window, log_q, var_ls_ref, success, path)
    if root_window: root_window.after(100, lambda: check_clamav_download_progress(root_window, prog_dialog, prog_label, prog_bar, download_q_local, dl_thread, log_q, post_download_cb_for_checker))
