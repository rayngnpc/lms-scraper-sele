# lms_auditor/utils/system_ops.py
import platform
import ctypes
import os # For os.path.basename
import sys # For traceback
import traceback

# This function might need to log. We'll pass log_queue if necessary or let it print.
def run_elevated_windows_executable(executable_path, parameters=None, log_q=None): # Added log_q
    """
    Attempts to run an executable with elevation using 'runas' verb on Windows.
    `executable_path`: Full path to .exe or .msi.
    `parameters`: String of parameters for the executable.
    Returns: (bool_success, message_string)
    """
    if platform.system() != "Windows":
        return False, "Elevation via 'runas' is a Windows-specific feature."

    try:
        file_to_run = executable_path
        current_parameters = parameters

        if executable_path.lower().endswith(".msi"):
            file_to_run = "msiexec.exe"
            if parameters is None:
                current_parameters = f'/i "{executable_path}"'
            elif "{msi_path}" in parameters:
                 current_parameters = parameters.replace("{msi_path}", executable_path)

        verb = "runas"
        if log_q: log_q.put(f"INFO_SYS_OPS: Attempting to launch elevated: {file_to_run} {current_parameters or ''}\n")
        else: print(f"INFO_SYS_OPS: Attempting to launch elevated: {file_to_run} {current_parameters or ''}")


        ret = ctypes.windll.shell32.ShellExecuteW(None, verb, file_to_run, current_parameters, None, 1)

        if ret <= 32:
            error_code = ctypes.get_last_error() if ret in [0, 2, 3, 5, 31] else ret
            if error_code == 1223:
                 msg_uac = f"INFO_SYS_OPS: User cancelled UAC prompt for {file_to_run}.\n"
                 if log_q: log_q.put(msg_uac)
                 else: print(msg_uac)
                 return False, f"User cancelled the UAC prompt for {os.path.basename(executable_path)}."
            msg_err_shell = f"ERROR_SYS_OPS: ShellExecuteW failed for {file_to_run}. Return: {ret}, LastError: {error_code}\n"
            if log_q: log_q.put(msg_err_shell)
            else: print(msg_err_shell)
            return False, f"Failed to start {os.path.basename(executable_path)} (ShellExecuteW code: {ret}, OS error: {error_code}). Check permissions or path."

        msg_succ_shell = f"INFO_SYS_OPS: {os.path.basename(executable_path)} launched with elevation request (or process already elevated).\n"
        if log_q: log_q.put(msg_succ_shell)
        else: print(msg_succ_shell)
        return True, f"{os.path.basename(executable_path)} launched. Please follow its prompts and complete its operations."

    except AttributeError:
        msg = "ERROR_SYS_OPS: ShellExecuteW is not available on this platform."
        if log_q: log_q.put(msg + "\n")
        else: print(msg)
        return False, "Elevation via ShellExecuteW is Windows-only."
    except Exception as e_shell:
        err_msg_shell = f"ERROR_SYS_OPS: Exception launching elevated '{executable_path}': {e_shell}\n{traceback.format_exc()}\n"
        if log_q: log_q.put(err_msg_shell)
        else: print(err_msg_shell, file=sys.stderr)
        return False, f"An unexpected error occurred while trying to launch {os.path.basename(executable_path)}: {e_shell}"