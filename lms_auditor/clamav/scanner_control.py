# lms_auditor/clamav/scanner_control.py
import os
import subprocess
import platform
import shutil
import ctypes
import traceback
from lms_auditor.config import app_settings

# Helper for logging from this module
def _log_message_sc(message_content, is_error=False):
    """Helper to log from scanner_control, ensuring newline and flush."""
    try:
        # Assuming app_settings.LOG_QUEUE is set by the main GUI thread
        q = app_settings.LOG_QUEUE
        if q and hasattr(q, 'put'):
            q.put(str(message_content) + "\n")
            return
    except AttributeError: # If app_settings.LOG_QUEUE doesn't exist or not set yet
        pass
    # Fallback to print
    print(str(message_content), flush=True)


def find_clamscan_executable_internal():
    scanner_cmd_config = getattr(app_settings, 'LOCAL_AV_SCANNER_COMMAND', 'clamscan')
    if os.path.isabs(scanner_cmd_config) and os.path.exists(scanner_cmd_config) and os.access(scanner_cmd_config, os.X_OK):
        return scanner_cmd_config
    scanner_base_name = os.path.basename(scanner_cmd_config)
    found_path_in_shutil = shutil.which(scanner_base_name)
    if found_path_in_shutil: return found_path_in_shutil
    if platform.system() == "Windows":
        if not scanner_base_name.lower().endswith(".exe"): scanner_base_name_exe = scanner_base_name + ".exe"
        else: scanner_base_name_exe = scanner_base_name
        program_files_variants = [os.environ.get("ProgramFiles", "C:\\Program Files"), os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")]
        program_files_variants = [pf for pf in program_files_variants if pf] # Filter None
        if not program_files_variants: program_files_variants.extend(["C:\\Program Files", "C:\\Program Files (x86)"])

        clamav_install_names = ["ClamAV", "ClamAV-unofficial"]
        clamav_exe_relative_locations = [scanner_base_name_exe, os.path.join("bin", scanner_base_name_exe)]
        for pf_path_base in program_files_variants:
            for install_name in clamav_install_names:
                clamav_root_dir = os.path.join(pf_path_base, install_name)
                for rel_exe_loc in clamav_exe_relative_locations:
                    potential_path = os.path.join(clamav_root_dir, rel_exe_loc)
                    if os.path.exists(potential_path) and os.access(potential_path, os.X_OK):
                        return potential_path
    if not os.path.isabs(scanner_cmd_config):
        potential_cwd_path = os.path.abspath(scanner_cmd_config)
        if os.path.exists(potential_cwd_path) and os.access(potential_cwd_path, os.X_OK):
            return potential_cwd_path
    _log_message_sc(f"WARN_SCANNER_CONTROL: clamscan executable '{scanner_cmd_config}' not found.", is_error=True)
    return None

def find_freshclam_executable():
    """Tries to find freshclam.exe, similar to clamscan."""
    log_q_local = getattr(app_settings, 'LOG_QUEUE', None) 
    if platform.system() != "Windows": 
        fc_path = shutil.which("freshclam")
        if fc_path and log_q_local: log_q_local.put(f"DEBUG_SCANNER_CONTROL: Found freshclam (non-Windows) at {fc_path}\n")
        return fc_path

    freshclam_base_name = "freshclam.exe"
    found_path_in_shutil = shutil.which(freshclam_base_name)
    if found_path_in_shutil:
        if log_q_local: log_q_local.put(f"DEBUG_SCANNER_CONTROL: Found freshclam.exe via shutil.which: {found_path_in_shutil}\n")
        return found_path_in_shutil

    program_files_variants = [os.environ.get("ProgramFiles", "C:\\Program Files"), os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")]
    program_files_variants = [pf for pf in program_files_variants if pf]
    if not program_files_variants: program_files_variants.extend(["C:\\Program Files", "C:\\Program Files (x86)"])

    clamav_install_names = ["ClamAV", "ClamAV-unofficial"]
    freshclam_relative_locations = [freshclam_base_name, os.path.join("bin", freshclam_base_name)]

    for pf_path_base in program_files_variants:
        for install_name in clamav_install_names:
            clamav_root_dir = os.path.join(pf_path_base, install_name)
            for rel_exe_loc in freshclam_relative_locations:
                potential_path = os.path.join(clamav_root_dir, rel_exe_loc)
                if os.path.exists(potential_path) and os.access(potential_path, os.X_OK):
                    if log_q_local: log_q_local.put(f"DEBUG_SCANNER_CONTROL: Found freshclam.exe in common location: {potential_path}\n")
                    return potential_path

    if log_q_local: log_q_local.put(f"WARN_SCANNER_CONTROL: freshclam.exe not found in PATH or common locations.\n")
    return None

def run_freshclam_as_admin(freshclam_path):
    """Attempts to run freshclam.exe with elevation."""
    log_q_local = getattr(app_settings, 'LOG_QUEUE', None)
    try:
        if log_q_local: log_q_local.put(f"INFO_SCANNER_CONTROL: Attempting to launch freshclam.exe: {freshclam_path}\n")
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", freshclam_path, None, None, 1) # SW_SHOWNORMAL
        if ret <= 32:
            error_code = ctypes.get_last_error() if ret in [0, 2, 3, 5, 31] else ret
            if error_code == 1223: # ERROR_CANCELLED
                 if log_q_local: log_q_local.put("INFO_SCANNER_CONTROL: User cancelled UAC for freshclam.exe.\n")
                 return False, "User cancelled UAC prompt for freshclam.exe."
            if log_q_local: log_q_local.put(f"ERROR_SCANNER_CONTROL: ShellExecuteW failed for freshclam.exe. Return: {ret}, LastError: {error_code}\n")
            return False, f"Failed to start freshclam.exe (code: {ret}, error: {error_code})."
        if log_q_local: log_q_local.put("INFO_SCANNER_CONTROL: freshclam.exe launched with elevation request.\n")
        return True, "freshclam.exe launched. Please observe its console window and wait for it to complete (it will close automatically or ask you to press a key)."
    except Exception as e_shell:
        if log_q_local: log_q_local.put(f"ERROR_SCANNER_CONTROL: Exception launching freshclam.exe '{freshclam_path}': {e_shell}\n{traceback.format_exc()}\n")
        return False, f"Error launching freshclam.exe: {e_shell}"


def scan_file_locally(filepath, force_scan_for_test=False):
    log_q_local = getattr(app_settings, 'LOG_QUEUE', None)
    if not force_scan_for_test and not app_settings.ENABLE_LOCAL_FILE_SCANS:
        return {"status": "LocalScanDisabled", "infected": None, "details": "Local scanning not enabled in config.", "needs_freshclam": False}

    if not os.path.exists(filepath):
        return {"status": "FileNotFoundForScan", "infected": None, "details": f"File not found at {filepath}", "needs_freshclam": False}

    scanner_executable_path = find_clamscan_executable_internal()
    if not scanner_executable_path:
        return {"status": "ScannerNotFoundAtScanTime", "infected": None, "details": "Clamscan not found.", "needs_freshclam": False}

    absolute_filepath = os.path.abspath(filepath)

    if not os.path.exists(absolute_filepath):
        return {"status": "FileNotFoundAtScanCommand", "infected": None, "details": f"File vanished: {absolute_filepath}", "needs_freshclam": False}

    log_msg_prefix_str = f"    Scanning ({os.path.basename(scanner_executable_path)}): {os.path.basename(absolute_filepath)} ..."
    if log_q_local: log_q_local.put(log_msg_prefix_str)
    else: print(log_msg_prefix_str, end="", flush=True)

    scan_result = {"status": "ScanFailed", "infected": None, "engine": scanner_executable_path, "details": "Scan did not complete.", "needs_freshclam": False}
    command = [scanner_executable_path, "--stdout", "--no-summary", "-i", absolute_filepath] # -i for infected files only
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=False, timeout=300)
        output_details = (process.stdout.strip() + "\n" + process.stderr.strip()).strip()

        if process.returncode == 0: # Clean (no output on stdout if -i is used and file is clean)
            scan_result.update({"status": "Clean", "infected": False, "details": "No threats detected."})
            if log_q_local: log_q_local.put(" Clean.\n")
            else: print(" Clean.")
        elif process.returncode == 1: # Infected (stdout will have details)
            scan_result.update({"status": "Infected", "infected": True, "details": process.stdout.strip() or "Threat detected"})
            if log_q_local: log_q_local.put(f" INFECTED! Details: {scan_result['details']}\n")
            else: print(f" INFECTED! Details: {scan_result['details']}")
        else: # Other error codes (like 2 for ClamAV errors)
            scan_result.update({"status": "ScanError", "infected": None, "details": output_details or f"ClamAV error (code {process.returncode})"})
            log_suffix_str = f" Scan Error (code {process.returncode}). Details: {scan_result['details']}\n"
            if log_q_local: log_q_local.put(log_suffix_str)
            else: print(log_suffix_str)

            details_lower = scan_result['details'].lower()
            db_error_indicators = [
                "libclamav error: cl_load(): no such file or directory",
                "no supported database files found in",
                "can't open file or directory", 
                "cli_loaddbdir"
            ]
            for indicator in db_error_indicators:
                if indicator in details_lower:
                    if indicator == "can't open file or directory" and \
                       not ((".cvd" in details_lower or ".cld" in details_lower or "database" in details_lower) and "daily" not in absolute_filepath.lower()):
                        continue
                    scan_result["needs_freshclam"] = True
                    if log_q_local: log_q_local.put(f"    Detected database loading error (indicator: '{indicator}'); freshclam might be needed.\n")
                    break
    except subprocess.TimeoutExpired:
        scan_result.update({"status": "ScanTimeout", "details": "Scan timed out."})
        if log_q_local: log_q_local.put(" Scan Timeout.\n")
        else: print(" Scan Timeout.")
    except FileNotFoundError:
        scan_result.update({"status": "ScannerNotFound", "infected": None, "details": f"Scanner command '{scanner_executable_path}' not found when trying to run."})
        if log_q_local: log_q_local.put(f" ERROR: Scanner command '{scanner_executable_path}' not found during subprocess.run.\n")
    except Exception as e:
        scan_result.update({"status": "ScanException", "details": str(e)})
        if log_q_local: log_q_local.put(f" Scan Exception: {e}\n{traceback.format_exc()}\n")
        else: print(f" Scan Exception: {e}\n{traceback.format_exc()}")
    return scan_result


def scan_directory_and_map_results(directory_path):
    _log_message_sc(f"DEBUG_SCANNER_CONTROL: scan_directory_and_map_results CALLED for directory: {directory_path}")

    # Convert directory_path to an absolute path from the start for consistency
    abs_directory_path = os.path.abspath(directory_path)
    _log_message_sc(f"DEBUG_SCANNER_CONTROL: Absolute directory path for scan: {abs_directory_path}")

    scanner_executable_path = find_clamscan_executable_internal()
    results_map = {} # Keys will be absolute paths

    if os.path.isdir(abs_directory_path):
        for root, _, files_in_fs in os.walk(abs_directory_path): # Walk the absolute path
            for f_name in files_in_fs:
                # Create absolute path for files found by os.walk
                abs_f_path_walk = os.path.normpath(os.path.join(root, f_name))
                results_map[abs_f_path_walk] = {
                    "status": "ScanStatusUnknown", "infected": None,
                    "details": "File present but not (yet) explicitly reported by batch scan.",
                    "engine": scanner_executable_path, "needs_freshclam": False
                }
        _log_message_sc(f"DEBUG_SCANNER_CONTROL: Pre-populated results_map for {abs_directory_path} with {len(results_map)} files (using absolute paths).")
    else:
        _log_message_sc(f"ERROR_SCANNER_CONTROL: Path provided is NOT a directory after abspath: {abs_directory_path}", is_error=True)
        return results_map # Return empty if not a directory

    if not scanner_executable_path:
        _log_message_sc(f"ERROR_SCANNER_CONTROL: Clamscan executable NOT FOUND. Cannot scan directory {abs_directory_path}", is_error=True)
        for f_path_key_no_scanner in results_map.keys(): # Iterate over keys from os.walk
            results_map[f_path_key_no_scanner].update({
                "status": "ScannerNotFoundAtScanTime",
                "details": "Clamscan executable not found for batch scan."
            })
        _log_message_sc(f"DEBUG_SCANNER_CONTROL: scan_directory_and_map_results for {abs_directory_path} RETURNING due to no scanner. Map size: {len(results_map)}")
        return results_map

    # Pass the absolute directory path to clamscan.
    # --recursive is often default for directories with clamscan, but can be added if needed.
    command = [scanner_executable_path, "--stdout", "--no-summary", abs_directory_path]
    _log_message_sc(f"DEBUG_SCANNER_CONTROL: Batch scanning directory: {abs_directory_path} with command: {' '.join(command)}")

    try:
        _log_message_sc(f"DEBUG_SCANNER_CONTROL: About to run subprocess for: {abs_directory_path}")
        process = subprocess.run(command, capture_output=True, text=True, check=False, timeout=1800) # 30 min timeout
        _log_message_sc(f"DEBUG_SCANNER_CONTROL: Subprocess for {abs_directory_path} COMPLETED.")

        stdout_from_clamscan = process.stdout.strip()
        stderr_from_clamscan = process.stderr.strip()
        debug_clam_output_msg = (f"DEBUG_SCANNER_CONTROL: Clamscan for '{abs_directory_path}' raw output:\n"
                                 f"  Return Code: {process.returncode}\n"
                                 f"  Stdout: >>>\n{stdout_from_clamscan}\n<<<\n"
                                 f"  Stderr: >>>\n{stderr_from_clamscan}\n<<<")
        _log_message_sc(debug_clam_output_msg)

        stdout_lines = stdout_from_clamscan.splitlines()
        stderr_lines = stderr_from_clamscan.splitlines()

        needs_freshclam_from_this_scan = False
        global_error_details_from_stderr = ""

        if stderr_lines:
            global_error_details_from_stderr = "\n".join(stderr_lines)
            details_lower = global_error_details_from_stderr.lower()
            db_error_indicators = [
                "libclamav error: cl_load(): no such file or directory",
                "no supported database files found in", "cli_loaddbdir",
            ]
            for indicator in db_error_indicators:
                if indicator in details_lower:
                    needs_freshclam_from_this_scan = True
                    _log_message_sc(f"DEBUG_SCANNER_CONTROL:    Batch scan of {abs_directory_path} detected database error (stderr); freshclam might be needed.")
                    break
        
        # Apply global DB status to all files found by os.walk for this directory
        for f_path_key_db_update in results_map.keys():
            # Check if the file actually belongs to the directory being scanned, 
            # to avoid cross-contamination if results_map were ever global.
            # For current design (results_map is local), this check is mostly for safety.
            if os.path.normpath(abs_directory_path) in os.path.normpath(f_path_key_db_update):
                 results_map[f_path_key_db_update]["needs_freshclam"] = needs_freshclam_from_this_scan

        processed_files_from_stdout = set() # Keep track of files clamscan explicitly reported on
        for line in stdout_lines:
            line_strip = line.strip()
            if not line_strip: continue
            
            parts = line_strip.split(": ", 1)
            if len(parts) == 2:
                filepath_raw_from_scan = parts[0].strip()
                # Ensure the path from clamscan is treated as absolute and normalized for consistent map keys.
                # Clamscan (on Windows at least) usually outputs absolute paths if given an absolute dir.
                filepath_from_scan = os.path.normpath(os.path.abspath(filepath_raw_from_scan))
                
                result_str = parts[1].strip()
                
                # If clamscan reports a path not in our os.walk map (e.g., it followed a symlink os.walk didn't), add it.
                if filepath_from_scan not in results_map:
                    _log_message_sc(f"WARN_SCANNER_CONTROL: Path '{filepath_from_scan}' from clamscan stdout not in pre-populated map. Adding it.")
                    results_map[filepath_from_scan] = { 
                        "status": "ScanStatusUnknown", # Will be updated below
                        "infected": None,
                        "details": "File reported by Clamscan but not initially found by os.walk.",
                        "engine": scanner_executable_path,
                        "needs_freshclam": needs_freshclam_from_this_scan
                    }
                
                processed_files_from_stdout.add(filepath_from_scan) # Mark as processed from stdout
                
                current_file_result = results_map[filepath_from_scan] # Get the dict for this file
                current_file_result.update({ # Update it with common fields
                    "engine": scanner_executable_path, # Redundant if already set, but safe
                    "needs_freshclam": needs_freshclam_from_this_scan # Ensure it's set
                })

                if result_str == "OK":
                    current_file_result.update({"status": "Clean", "infected": False, "details": "No threats detected."})
                elif " FOUND" in result_str.upper():
                    current_file_result.update({"status": "Infected", "infected": True, "details": result_str})
                elif " ERROR" in result_str.upper() or "Can't open file".lower() in result_str.lower():
                    current_file_result.update({"status": "ScanErrorOnFile", "infected": None, "details": result_str})
                else: 
                    current_file_result.update({"status": "ScanOutputUnrecognized", "infected": None, "details": result_str})
            else:
                _log_message_sc(f"WARN_SCANNER_CONTROL: Unparseable line from clamscan (directory scan output for {abs_directory_path}): {line_strip}")
        
        # After processing stdout, check for files os.walk found but clamscan didn't explicitly mention.
        # These would still have "ScanStatusUnknown". If the overall clamscan process had an error (exit code),
        # these should probably be marked as "ScanErrorGeneral".
        if process.returncode not in [0, 1]: # 0 for all clean, 1 if any infected
            _log_message_sc(f"WARN_SCANNER_CONTROL: Clamscan process for {abs_directory_path} exited with code {process.returncode}. Stderr: {global_error_details_from_stderr}")
            for fp_key_general_error, res_dict_general_error in results_map.items():
                # Ensure we're only modifying files from the current directory context
                if os.path.normpath(abs_directory_path) in os.path.normpath(fp_key_general_error):
                    if res_dict_general_error["status"] in ["ScanStatusUnknown", "Clean"]: # Don't override more specific statuses like "Infected"
                        res_dict_general_error["status"] = "ScanErrorGeneral"
                        res_dict_general_error["details"] = (f"Batch scan issue (clamscan exit code {process.returncode}). "
                                                   f"Original detail: {res_dict_general_error.get('details', '')} "
                                                   f"Stderr: {global_error_details_from_stderr}").strip()
                        # needs_freshclam should already be set based on stderr parsing
    
    except subprocess.TimeoutExpired:
        _log_message_sc(f"ERROR_SCANNER_CONTROL: Timeout batch scanning directory {abs_directory_path}", is_error=True)
        for f_path_key_timeout in results_map.keys():
            if os.path.normpath(abs_directory_path) in os.path.normpath(f_path_key_timeout):
                results_map[f_path_key_timeout].update({
                    "status": "ScanTimeout", "infected": None,
                    "details": "Batch scan for directory timed out.",
                    "engine": scanner_executable_path # needs_freshclam already set
                })
    except Exception as e_batch_scan_generic:
        _log_message_sc(f"ERROR_SCANNER_CONTROL: Exception during batch scan of {abs_directory_path}: {e_batch_scan_generic}\n{traceback.format_exc()}", is_error=True)
        for f_path_key_exception in results_map.keys():
            if os.path.normpath(abs_directory_path) in os.path.normpath(f_path_key_exception):
                results_map[f_path_key_exception].update({
                    "status": "ScanException", "infected": None,
                    "details": f"Batch scan exception: {e_batch_scan_generic}",
                    "engine": scanner_executable_path
                })
            
    _log_message_sc(f"DEBUG_SCANNER_CONTROL: scan_directory_and_map_results for {abs_directory_path} FINISHED. RETURNING map with {len(results_map)} entries. First 5 keys: {list(results_map.keys())[:5]}...")
    return results_map