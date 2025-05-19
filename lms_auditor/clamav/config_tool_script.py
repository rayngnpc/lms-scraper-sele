# configure_clamav.py
import os
import shutil
import re
import sys
import ctypes

def show_message(title, message, style=0):
    if sys.stdout.isatty():
        print(f"[{title}] {message}")
    else:
        ctypes.windll.user32.MessageBoxW(0, message, title, style)

def configure_clamav_files():
    log_messages = [] # Initialize log_messages at the beginning

    # Determine Program Files paths
    pf = os.environ.get("ProgramFiles", "C:\\Program Files")
    pf_x86 = os.environ.get("ProgramFiles(x86)") # This might be None on a 32-bit OS

    possible_clamav_dirs = []
    possible_clamav_dirs.append(os.path.join(pf, "ClamAV"))
    if pf_x86: # Only add if ProgramFiles(x86) exists
        possible_clamav_dirs.append(os.path.join(pf_x86, "ClamAV"))
    
    # Deduplicate in case pf and pf_x86 somehow point to the same location (highly unlikely)
    # and ensure order (e.g. check pf_x86 first if you expect 32-bit to be more common for this tool)
    # For now, the order is fine.
    
    actual_clamav_dir = None
    for cand_dir in possible_clamav_dirs:
        # A more reliable check is looking for a key executable
        # For freshclam.conf, freshclam.exe is key. For clamd.conf, clamd.exe or clamscan.exe.
        # Let's check for freshclam.exe as freshclam.conf is primary.
        test_exe_path = os.path.join(cand_dir, "freshclam.exe")
        if os.path.isdir(cand_dir) and os.path.exists(test_exe_path):
            actual_clamav_dir = cand_dir
            log_messages.append(f"INFO: Found ClamAV installation at: {actual_clamav_dir} (freshclam.exe present)")
            break # Found a valid ClamAV directory
    
    if not actual_clamav_dir:
        log_messages.append("ERROR: ClamAV installation directory not found in standard Program Files locations containing freshclam.exe.")
        final_message = "\n".join(log_messages)
        show_message("ClamAV Config Error", final_message, 16)
        return False

    conf_examples_dir = os.path.join(actual_clamav_dir, "conf_examples")
    if not os.path.isdir(conf_examples_dir):
        log_messages.append(f"ERROR: 'conf_examples' directory not found at {conf_examples_dir}.")
        final_message = "\n".join(log_messages)
        show_message("ClamAV Config Error", final_message, 16)
        return False # Cannot proceed without examples

    configs_to_process = {
        "freshclam.conf": "freshclam.conf.sample",
        "clamd.conf": "clamd.conf.sample"
    }
    
    all_successful = True

    for conf_name, sample_name in configs_to_process.items():
        target_conf_path = os.path.join(actual_clamav_dir, conf_name) # Use actual_clamav_dir
        sample_conf_path = os.path.join(conf_examples_dir, sample_name) # Use conf_examples_dir (derived from actual_clamav_dir)

        log_messages.append(f"DEBUG: Checking for sample: {sample_conf_path}") # Explicit log
        if not os.path.exists(sample_conf_path):
            log_messages.append(f"WARN: Sample file {sample_name} not found at {sample_conf_path}. Skipping {conf_name}.")
            # Don't mark all_successful as False for this, as it might be intentional if user removed samples for one config
            continue

        needs_creating_or_fixing = False
        log_messages.append(f"DEBUG: Checking target config: {target_conf_path}") # Explicit log
        if not os.path.exists(target_conf_path):
            needs_creating_or_fixing = True
            log_messages.append(f"INFO: {conf_name} does not exist. Will create from sample.")
        else:
            try:
                with open(target_conf_path, 'r', encoding='utf-8', errors='ignore') as f_check:
                    content_check = f_check.read()
                if re.search(r"^\s*Example\s*$", content_check, re.MULTILINE):
                    needs_creating_or_fixing = True
                    log_messages.append(f"INFO: {conf_name} exists but contains uncommented 'Example'. Will fix.")
                else:
                    log_messages.append(f"INFO: {conf_name} exists and seems configured (no uncommented 'Example'). Leaving as is.")
            except Exception as e_read_check:
                log_messages.append(f"WARN: Could not read existing {target_conf_path} to check for 'Example': {e_read_check}. Will attempt to recreate.")
                needs_creating_or_fixing = True

        if needs_creating_or_fixing:
            log_messages.append(f"INFO: Processing {sample_name} to create/fix {conf_name}...")
            try:
                with open(sample_conf_path, 'r', encoding='utf-8', errors='ignore') as f_sample:
                    lines = f_sample.readlines()
                
                modified_lines = []
                example_commented_this_file = False
                for line_num, line in enumerate(lines):
                    # More precise regex: exactly "Example" with optional whitespace, on its own line
                    if re.fullmatch(r"\s*Example\s*\n?", line) or re.fullmatch(r"\s*Example\s*", line.strip()):
                        modified_lines.append("# " + line.lstrip()) # Comment it out
                        example_commented_this_file = True
                        log_messages.append(f"DEBUG: Commented 'Example' at line {line_num+1} in {sample_name}")
                    else:
                        modified_lines.append(line)
                
                if not example_commented_this_file:
                     # Check if "Example" might exist without being a full line match (less likely to be the one we need to comment)
                    raw_content_for_failsafe = "".join(lines)
                    if "Example" in raw_content_for_failsafe and not re.search(r"^#\s*Example", raw_content_for_failsafe, re.MULTILINE):
                        log_messages.append(f"WARN: 'Example' line might not have been the target one or was missed by regex in {sample_name}. Check manually if issues persist.")

                with open(target_conf_path, 'w', encoding='utf-8') as f_target:
                    f_target.writelines(modified_lines)
                log_messages.append(f"INFO: Successfully created/updated {target_conf_path} from {sample_name}.")

            except PermissionError as e_perm:
                 log_messages.append(f"ERROR: Permission denied writing to {target_conf_path}. Ensure script has admin rights. Details: {e_perm}")
                 all_successful = False
            except Exception as e_proc:
                log_messages.append(f"ERROR: Could not process {sample_name} for {conf_name}: {e_proc}")
                all_successful = False
    
    final_summary_message = "ClamAV Configuration Processing Summary:\n" + "\n".join(log_messages)
    if all_successful:
        show_message("ClamAV Configuration", final_summary_message, 0)
    else:
        show_message("ClamAV Configuration Warning", final_summary_message, 48)
        
    return all_successful

if __name__ == "__main__":
    is_admin = False
    try: is_admin = os.getuid() == 0
    except AttributeError:
        try: is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception: pass

    if not is_admin:
        show_message("Admin Rights Required", "This script needs Admin rights to modify Program Files.", 16)
        sys.exit(1)
        
    configure_clamav_files()
    if sys.stdout.isatty():
        input("Configuration finished. Press Enter to exit.")