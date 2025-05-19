# lms_auditor/gui/main_app_window.py
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font as tkFont
import threading
import queue
import os
import sys
import traceback
from PIL import Image, ImageTk

# Imports from our restructured project
from lms_auditor.config import app_settings
from lms_auditor.core.auditor import audit_lms_courses_fully, set_events_from_gui

# GUI specific modules
from . import clamav_gui_manager # Will call functions from here
from . import ui_helpers         # Will call functions from here

def show_info_message(title, message):
    messagebox.showinfo(title, message, icon=messagebox.INFO)

class LMSAuditorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LMS Content Auditor v1.0.0 - GUI - Phuoc Chau") # Version bump
        self.root.geometry("850x750")
        self.root.minsize(700, 600)

        self.log_queue = queue.Queue()
        self.audit_thread_continue_event = threading.Event()
        self.audit_thread_stop_event = threading.Event()

        # Initialize fonts and styles using ui_helpers
        ui_helpers.initialize_fonts(self.log_queue) # Pass log_queue
        ui_helpers.apply_ttk_styles(self.log_queue)   # Pass log_queue

        self.root.configure(bg=ui_helpers.COLOR_PRIMARY_BG)

        self._setup_variables()
        self._create_widgets()
        self._initial_ui_state()

        # Pass log_queue to other modules if they have a setter (more advanced)
        # For now, functions in other modules will take log_queue as a parameter if needed.
        # e.g., core.lms_handler.log_queue = self.log_queue (if lms_handler had such a global)

        self.root.after(100, self.update_log_area)

    def _setup_variables(self):
        # --- Variables for GUI elements ---
        self.entry_moodle_url_var = tk.StringVar(value=getattr(app_settings, 'MOODLE_LOGIN_URL', 'https://moodleprod.murdoch.edu.au'))
        self.entry_webdriver_path_var = tk.StringVar(value=getattr(app_settings, 'driver_path', 'E:\\MyProject\\lms-scraper-selenium-v1.0.0-GUI\\chromedriver.exe'))
        self.entry_output_base_dir_var = tk.StringVar(value=getattr(app_settings, 'MAIN_OUTPUT_DIRECTORY_BASE', 'lms_audit_runs_final'))
        self.entry_vt_api_key_var = tk.StringVar(value=getattr(app_settings, 'VIRUSTOTAL_API_KEY', ''))
        self.var_enable_vt = tk.BooleanVar(value=getattr(app_settings, 'ENABLE_VIRUSTOTAL_CHECKS', False))
        self.entry_max_pages_var = tk.StringVar(value=str(getattr(app_settings, 'MAX_PAGES_TO_CRAWL_PER_COURSE', 1)))
        self.var_enable_local_scan = tk.BooleanVar(value=getattr(app_settings, 'ENABLE_LOCAL_FILE_SCANS', False))
        self.var_fetch_external_html = tk.BooleanVar(value=getattr(app_settings, 'FETCH_EXTERNAL_LINK_HTML', False))
        self.entry_fetch_timeout_var = tk.StringVar(value=str(getattr(app_settings, 'EXTERNAL_LINK_HTML_FETCH_TIMEOUT', 2)))
        self.var_enable_quick_grab = tk.BooleanVar(value=getattr(app_settings, 'ENABLE_QUICK_GRAB_CONTENT_PAGES', False))
         ### NEW GSB Variables ###
        self.var_enable_gsb = tk.BooleanVar(value=getattr(app_settings, 'ENABLE_GOOGLE_SAFE_BROWSING_CHECKS', False))
        self.entry_gsb_api_key_var = tk.StringVar(value=getattr(app_settings, 'GOOGLE_SAFE_BROWSING_API_KEY', ''))
        ### NEW Metadefender Variables ###
        self.var_enable_metadefender = tk.BooleanVar(value=getattr(app_settings, 'ENABLE_METADEFENDER_CHECKS', False))
        self.entry_metadefender_api_key_var = tk.StringVar(value=getattr(app_settings, 'METADEFENDER_API_KEY', ''))

    def _create_widgets(self):
        # --- Configuration Frame ---
        config_labelframe = ttk.LabelFrame(self.root, text="Auditor Configuration", padding=(10, 10))
        config_labelframe.pack(padx=10, pady=(10,5), fill="x", side=tk.TOP, anchor="n")

        author_name_text = "Author: Nguyen Phuoc Chau"
        author_font_tuple = (ui_helpers.FONT_GENERAL_FAMILY, 8, "italic")
        author_display_label = ttk.Label(config_labelframe, text=author_name_text, font=author_font_tuple, style="TLabel")
        author_display_label.place(relx=1.0, x=-12, rely=0.0, y=-14, anchor="ne")

        config_labelframe.columnconfigure(0, weight=0, minsize=120)
        config_labelframe.columnconfigure(1, weight=0)
        config_labelframe.columnconfigure(2, weight=1)
        config_labelframe.columnconfigure(3, weight=0)

        # --- ADD LOGO ---
        try:
            # Get the directory of the current script (main_app_window.py)
            current_file_dir = os.path.dirname(os.path.abspath(__file__)) # This will be /path/to/your_project_folder/lms_auditor/gui

            logo_filename = "university-logo.png"
            # Construct the path to the logo relative to this script's location
            logo_path = os.path.join(current_file_dir, "assets", "images", logo_filename)

            if self.log_queue: # Check if log_queue exists before putting
                self.log_queue.put(f"DEBUG_GUI: Attempting to load logo from: {logo_path}\n")
            else:
                print(f"DEBUG_GUI: Attempting to load logo from: {logo_path}")


            if os.path.exists(logo_path):
                img_pil = Image.open(logo_path)
                desired_height = 90 # Adjust as needed
                img_w, img_h = img_pil.size
                if img_h > 0: # Ensure height is not zero to prevent division by zero
                    aspect_ratio = img_w / img_h
                    new_width = int(desired_height * aspect_ratio)
                    if new_width > 0: # Ensure width is also positive
                        # Use Image.Resampling.LANCZOS for Pillow 9.0.0+
                        # Use Image.ANTIALIAS for older versions
                        try:
                            img_resized = img_pil.resize((new_width, desired_height), Image.Resampling.LANCZOS)
                        except AttributeError:
                            img_resized = img_pil.resize((new_width, desired_height), Image.ANTIALIAS) # Fallback
                    else: # Should not happen if desired_height > 0 and aspect_ratio is sensible
                        img_resized = img_pil 
                else: # Should not happen for a valid image
                    img_resized = img_pil 

                # Keep a reference to the image object on the root window or self to prevent garbage collection
                self.root.logo_tk_image = ImageTk.PhotoImage(img_resized) 
                logo_label_widget = ttk.Label(config_labelframe, image=self.root.logo_tk_image, style="TLabel")
                logo_label_widget.grid(row=0, column=0, rowspan=3, padx=(0, 20), pady=10, sticky="nw")
            else:
                error_message = f"WARNING_APP: Logo image not found at path: {logo_path}\n"
                if self.log_queue: self.log_queue.put(error_message)
                else: print(error_message, file=sys.stderr)
                # Fallback label if logo is missing
                logo_label_widget = ttk.Label(config_labelframe, text="[Logo Missing]", font=(ui_helpers.FONT_GENERAL_FAMILY, 10, "italic"), style="TLabel")
                logo_label_widget.grid(row=0, column=0, rowspan=3, padx=(0, 20), pady=10, sticky="nw")
        except Exception as e_logo:
            error_message = f"ERROR_APP: Could not load or display logo: {e_logo}\n{traceback.format_exc()}\n"
            if self.log_queue: self.log_queue.put(error_message)
            else: print(error_message, file=sys.stderr)
            if config_labelframe.winfo_exists(): # Check if frame is still valid
                logo_label_widget = ttk.Label(config_labelframe, text="[Logo Load Error]", font=(ui_helpers.FONT_GENERAL_FAMILY, 10), style="TLabel")
                logo_label_widget.grid(row=0, column=0, rowspan=3, padx=(0, 20), pady=10, sticky="nw")
             # --- END LOGO ---


        # Row 0: Moodle Login URL
        ttk.Label(config_labelframe, text="Moodle Login URL:").grid(row=0, column=1, padx=5, pady=3, sticky="w")
        self.entry_moodle_url = ttk.Entry(config_labelframe, width=60, textvariable=self.entry_moodle_url_var)
        self.entry_moodle_url.grid(row=0, column=2, columnspan=2, padx=5, pady=3, sticky="ew")

        # Row 1: WebDriver Path
        ttk.Label(config_labelframe, text="WebDriver Path:").grid(row=1, column=1, padx=5, pady=3, sticky="w")
        self.entry_webdriver_path = ttk.Entry(config_labelframe, width=50, textvariable=self.entry_webdriver_path_var)
        self.entry_webdriver_path.grid(row=1, column=2, padx=5, pady=3, sticky="ew")
        self.btn_browse_webdriver = ttk.Button(config_labelframe, text="Browse...", command=lambda: ui_helpers.browse_webdriver_path(self.entry_webdriver_path_var))
        self.btn_browse_webdriver.grid(row=1, column=3, padx=5, pady=3, sticky="ew")

        # Row 2: Output Base Dir
        ttk.Label(config_labelframe, text="Output Base Dir:").grid(row=2, column=1, padx=5, pady=3, sticky="w")
        self.entry_output_base_dir = ttk.Entry(config_labelframe, width=50, textvariable=self.entry_output_base_dir_var)
        self.entry_output_base_dir.grid(row=2, column=2, padx=5, pady=3, sticky="ew")
        self.btn_browse_output = ttk.Button(config_labelframe, text="Browse...", command=lambda: ui_helpers.browse_output_dir(self.entry_output_base_dir_var))
        self.btn_browse_output.grid(row=2, column=3, padx=5, pady=3, sticky="ew")

        ttk.Separator(config_labelframe, orient='horizontal').grid(row=3, column=0, columnspan=4, sticky='ew', pady=8)

        # Row 4: Crawler Options (Part 1: Max Pages, Fetch Ext. HTML, Timeout)
        crawler_options_subframe_part1 = ttk.Frame(config_labelframe, style="TFrame")
        crawler_options_subframe_part1.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(0,2), padx=5)
        # ... (widgets inside crawler_options_subframe_part1 using pack) ...
        ttk.Label(crawler_options_subframe_part1, text="Max Pages/Course:").pack(side=tk.LEFT, padx=(0,2))
        self.entry_max_pages = ttk.Entry(crawler_options_subframe_part1, width=6, textvariable=self.entry_max_pages_var)
        self.entry_max_pages.pack(side=tk.LEFT, padx=(0,10))
        self.check_fetch_external_html = ttk.Checkbutton(crawler_options_subframe_part1, text="Fetch Ext. HTML", variable=self.var_fetch_external_html)
        self.check_fetch_external_html.pack(side=tk.LEFT, padx=(5,2))
        ttk.Label(crawler_options_subframe_part1, text="Timeout(s):").pack(side=tk.LEFT, padx=(5,2))
        self.entry_fetch_timeout = ttk.Entry(crawler_options_subframe_part1, width=5, textvariable=self.entry_fetch_timeout_var)
        self.entry_fetch_timeout.pack(side=tk.LEFT, padx=(0,5))


        # Row 5: Crawler Options (Part 2: Quick Grab)
        crawler_options_subframe_part2_quickgrab = ttk.Frame(config_labelframe, style="TFrame")
        crawler_options_subframe_part2_quickgrab.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(2,5), padx=5)
        # ... (widgets inside crawler_options_subframe_part2_quickgrab using its internal grid) ...
        self.check_enable_quick_grab = ttk.Checkbutton(crawler_options_subframe_part2_quickgrab, text="Enable Quick Grab (Content Pages)", variable=self.var_enable_quick_grab)
        self.check_enable_quick_grab.grid(row=0, column=0, sticky="w", padx=(0, 5))
        quick_grab_info_message = "Enabling Quick Grab makes page loading faster for course content.\n\nHowever, it might miss links that are loaded dynamically by JavaScript after the initial page load.\n\nUse with caution if you suspect complex pages; disable for maximum thoroughness."
        self.quick_grab_info_icon = ttk.Label(crawler_options_subframe_part2_quickgrab, text="ⓘ", cursor="hand2", font=(ui_helpers.FONT_GENERAL_FAMILY, 10, "bold"))
        self.quick_grab_info_icon.grid(row=0, column=1, sticky="w", padx=(2, 5))
        self.quick_grab_info_icon.bind("<Button-1>", lambda e: show_info_message("Quick Grab Information", quick_grab_info_message))
        self.quick_grab_info_icon.configure(foreground=ui_helpers.COLOR_ACCENT_HIGHLIGHT)
        
        # Row 6: Separator before Security Options
        ttk.Separator(config_labelframe, orient='horizontal').grid(row=6, column=0, columnspan=4, sticky='ew', pady=8)

        api_label_column_minsize_virustotal = 160
        api_label_column_minsize_googlesafebrowsing = 89
        api_label_column_minsize_metadefender = 97
        checkbox_right_padding = 15

        # Row 7: Security Options (VirusTotal) - Using grid
        security_options_subframe_vt = ttk.Frame(config_labelframe, style="TFrame")
        security_options_subframe_vt.grid(row=7, column=0, columnspan=4, sticky="ew", pady=(0,2), padx=5)
        security_options_subframe_vt.columnconfigure(0, weight=0) # Checkbox
        security_options_subframe_vt.columnconfigure(1, weight=0, minsize=api_label_column_minsize_virustotal) # API Key Label
        security_options_subframe_vt.columnconfigure(2, weight=1) # API Key Entry
        security_options_subframe_vt.columnconfigure(3, weight=0) # Info Icon
        self.check_enable_vt = ttk.Checkbutton(security_options_subframe_vt, text="Enable VirusTotal", variable=self.var_enable_vt)
        self.check_enable_vt.grid(row=0, column=0, sticky="w", padx=(0, checkbox_right_padding))
        ttk.Label(security_options_subframe_vt, text="VT API Key:").grid(row=0, column=1, sticky="e", padx=(0,2))
        self.entry_vt_api_key = ttk.Entry(security_options_subframe_vt, textvariable=self.entry_vt_api_key_var, show="*")
        self.entry_vt_api_key.grid(row=0, column=2, sticky="ew", padx=(0,5))
        vt_info_message = "VirusTotal checks URLs against a large database of antivirus engines and website scanners.\nRequires a free API key from virustotal.com.\nPublic API has rate limits (e.g., 4 requests/minute)."
        self.vt_info_icon = ttk.Label(security_options_subframe_vt, text="ⓘ", cursor="hand2", font=(ui_helpers.FONT_GENERAL_FAMILY, 10, "bold"))
        self.vt_info_icon.grid(row=0, column=3, sticky="w", padx=(2,0))
        self.vt_info_icon.bind("<Button-1>", lambda e: show_info_message("VirusTotal Information", vt_info_message))
        self.vt_info_icon.configure(foreground=ui_helpers.COLOR_ACCENT_HIGHLIGHT)


        # Row 8: Google Safe Browsing - Using the same grid configuration
        security_options_subframe_gsb = ttk.Frame(config_labelframe, style="TFrame")
        security_options_subframe_gsb.grid(row=8, column=0, columnspan=4, sticky="ew", pady=(2,2), padx=5)
        security_options_subframe_gsb.columnconfigure(0, weight=0) 
        security_options_subframe_gsb.columnconfigure(1, weight=0, minsize=api_label_column_minsize_googlesafebrowsing) 
        security_options_subframe_gsb.columnconfigure(2, weight=1) 
        security_options_subframe_gsb.columnconfigure(3, weight=0) 
        self.check_enable_gsb = ttk.Checkbutton(security_options_subframe_gsb, text="Enable Google Safe Browsing", variable=self.var_enable_gsb)
        self.check_enable_gsb.grid(row=0, column=0, sticky="w", padx=(0, checkbox_right_padding)) 
        ttk.Label(security_options_subframe_gsb, text="GSB API Key:").grid(row=0, column=1, sticky="e", padx=(0,2))
        self.entry_gsb_api_key = ttk.Entry(security_options_subframe_gsb, textvariable=self.entry_gsb_api_key_var, show="*")
        self.entry_gsb_api_key.grid(row=0, column=2, sticky="ew", padx=(0,5))
        gsb_info_message = "Google Safe Browsing (via Web Risk API) checks URLs against Google's lists of unsafe web resources.\nRequires an API key from Google Cloud Platform.\nPrimarily for widely known threats."
        self.gsb_info_icon = ttk.Label(security_options_subframe_gsb, text="ⓘ", cursor="hand2", font=(ui_helpers.FONT_GENERAL_FAMILY, 10, "bold"))
        self.gsb_info_icon.grid(row=0, column=3, sticky="w", padx=(2,0))
        self.gsb_info_icon.bind("<Button-1>", lambda e: show_info_message("Google Safe Browsing Information", gsb_info_message))
        self.gsb_info_icon.configure(foreground=ui_helpers.COLOR_ACCENT_HIGHLIGHT)


         # Row 9: Metadefender - Using the same grid configuration
        security_options_subframe_md = ttk.Frame(config_labelframe, style="TFrame")
        security_options_subframe_md.grid(row=9, column=0, columnspan=4, sticky="ew", pady=(2,5), padx=5)
        security_options_subframe_md.columnconfigure(0, weight=0)
        security_options_subframe_md.columnconfigure(1, weight=0, minsize=api_label_column_minsize_metadefender) 
        security_options_subframe_md.columnconfigure(2, weight=1)
        security_options_subframe_md.columnconfigure(3, weight=0)

        self.check_enable_metadefender = ttk.Checkbutton(security_options_subframe_md, text="Enable Metadefender Cloud", variable=self.var_enable_metadefender)
        self.check_enable_metadefender.grid(row=0, column=0, sticky="w", padx=(0, checkbox_right_padding))

        ttk.Label(security_options_subframe_md, text="MD API Key:").grid(row=0, column=1, sticky="e", padx=(0,2))
        self.entry_metadefender_api_key = ttk.Entry(security_options_subframe_md, textvariable=self.entry_metadefender_api_key_var, show="*")
        self.entry_metadefender_api_key.grid(row=0, column=2, sticky="ew", padx=(0,5))

        md_info_message = "Metadefender Cloud (OPSWAT) scans URLs using multiple commercial anti-malware engines.\nRequires an API key from opswat.com/metadefender-cloud.\nFree tier has limitations."
        self.md_info_icon = ttk.Label(security_options_subframe_md, text="ⓘ", cursor="hand2", font=(ui_helpers.FONT_GENERAL_FAMILY, 10, "bold"))
        self.md_info_icon.grid(row=0, column=3, sticky="w", padx=(2,0))
        self.md_info_icon.bind("<Button-1>", lambda e: show_info_message("Metadefender Cloud Information", md_info_message))
        self.md_info_icon.configure(foreground=ui_helpers.COLOR_ACCENT_HIGHLIGHT)

        # Row 10: Local Scan (ClamAV)
        local_scan_frame = ttk.Frame(config_labelframe, style="TFrame")
        local_scan_frame.grid(row=10, column=0, columnspan=4, sticky="ew", padx=5, pady=(5,10)) 
        # ... (internal widgets of local_scan_frame remain the same, usually a simple pack or grid for its own checkbox and icon) ...
        local_scan_frame.columnconfigure(0, weight=0) 
        local_scan_frame.columnconfigure(1, weight=0) 
        self.var_enable_local_scan.trace_add("write", self.handle_local_scan_toggle_proxy)
        self.check_enable_local_scan = ttk.Checkbutton(local_scan_frame, text="Enable Local File Scan (ClamAV)", variable=self.var_enable_local_scan)
        self.check_enable_local_scan.grid(row=0, column=0, sticky="w") 
        local_scan_info_message = "Enabling local file scanning will use ClamAV (if installed and configured) to scan downloaded files for viruses.\n\nThis process can significantly increase the audit time, especially if many files are downloaded.\n\nEnsure ClamAV is properly set up for this feature to work correctly."
        self.local_scan_info_icon = ttk.Label(local_scan_frame, text="ⓘ", cursor="hand2", font=(ui_helpers.FONT_GENERAL_FAMILY, 10, "bold"))
        self.local_scan_info_icon.grid(row=0, column=1, sticky="w", padx=(5, 0)) 
        self.local_scan_info_icon.bind("<Button-1>", lambda e: show_info_message("Local File Scan Information", local_scan_info_message))
        self.local_scan_info_icon.configure(foreground=ui_helpers.COLOR_ACCENT_HIGHLIGHT)

        # --- Action Buttons Frame ---
        action_frame = ttk.Frame(self.root, padding=(10, 5), style="TFrame")
        action_frame.pack(padx=10, pady=(0,5), fill="x", side=tk.TOP, anchor="n")
        self.btn_start_audit = ttk.Button(action_frame, text="Start Audit", command=self.start_audit, width=15)
        self.btn_start_audit.pack(side=tk.LEFT, padx=5, pady=5)
        self.btn_continue_after_login = ttk.Button(action_frame, text="Continue After Login", command=self.signal_continue_after_login, width=20, state=tk.DISABLED)
        self.btn_continue_after_login.pack(side=tk.LEFT, padx=5, pady=5)
        self.btn_stop_audit = ttk.Button(action_frame, text="Stop Audit", command=self.signal_stop_audit, width=15, state=tk.DISABLED)
        self.btn_stop_audit.pack(side=tk.LEFT, padx=5, pady=5)

        # --- Log Frame ---
        log_frame = ttk.LabelFrame(self.root, text="Audit Log", padding=(10,5))
        log_frame.pack(padx=10, pady=(0,10), fill="both", expand=True, side=tk.TOP, anchor="n")
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15, width=80,
                                         font=ui_helpers.FONT_LOG,
                                         bg=ui_helpers.COLOR_LOG_BG,
                                         fg=ui_helpers.COLOR_LOG_FG,
                                         insertbackground=ui_helpers.COLOR_TEXT_FG,
                                         selectbackground=ui_helpers.COLOR_ACCENT_HIGHLIGHT,
                                         selectforeground=ui_helpers.COLOR_BUTTON_TEXT,
                                         relief=tk.FLAT, borderwidth=0)
        self.log_area.pack(fill="both", expand=True, padx=5, pady=5)

    def _initial_ui_state(self):
        self.reset_ui_for_new_or_finished_audit(is_finished_run=False) # Initial setup state

    def handle_local_scan_toggle_proxy(self, *args):
        # This proxy calls the actual handler in clamav_gui_manager
        # It passes necessary references: root window, log_queue, and the BooleanVar
        clamav_gui_manager.handle_local_scan_toggle(
            self.root,
            self.log_queue,
            self.var_enable_local_scan,
            *args
        )

    def reset_ui_for_new_or_finished_audit(self, is_finished_run=True):
        action_context = "POST_AUDIT_RESET" if is_finished_run else "PRE_AUDIT_SETUP"
        self.log_queue.put(f"DEBUG_APP_UI_RESET: Called by {action_context}.\n")
        self.enable_config_fields()
        if self.btn_start_audit: self.btn_start_audit.config(state=tk.NORMAL, text="Start Audit")
        if self.btn_continue_after_login: self.btn_continue_after_login.config(state=tk.DISABLED)
        if self.btn_stop_audit: self.btn_stop_audit.config(state=tk.DISABLED)
        if self.root and self.root.winfo_exists(): self.root.update_idletasks()
        self.log_queue.put(f"DEBUG_APP_UI_RESET: {action_context} - UI reset complete.\n")


    def update_log_area(self):
        try:
            while True:
                message_item = self.log_queue.get_nowait()

                if message_item is None:
                    if self.log_area: self.log_area.insert(tk.END, "AUDIT PROCESS FINISHED OR STOPPED (sentinel received by ULA).\n")
                    self.reset_ui_for_new_or_finished_audit(is_finished_run=True)
                    if self.root and self.root.winfo_exists(): self.root.after(100, self.update_log_area)
                    return

                if isinstance(message_item, tuple) and len(message_item) > 0 and message_item[0] == "NEEDS_FRESHCLAM_PROMPT":
                    log_text_for_display = message_item[1] if len(message_item) > 1 else "ClamAV database error detected."
                    if self.log_area:
                        self.log_area.insert(tk.END, f"INFO_GUI: {log_text_for_display}\n")
                        self.log_area.see(tk.END)
                    # Call the handler from clamav_gui_manager
                    clamav_gui_manager.handle_freshclam_request_from_gui(self.log_queue)
                    continue

                log_text_for_display = message_item
                if isinstance(message_item, tuple) and len(message_item) > 1 and isinstance(message_item[0], str) and \
                   (message_item[0].startswith("progress") or message_item[0] in ["total_size", "progress_text", "progress_update"]):
                     log_text_for_display = message_item[1]

                if self.log_area:
                    self.log_area.insert(tk.END, str(log_text_for_display))
                    self.log_area.see(tk.END)

                msg_str_lower = str(log_text_for_display).lower()
                prompt_text1_lower = "action required: manually log in".lower()
                prompt_text2_lower = "then, use the 'continue after login' button in the gui.".lower()

                if prompt_text1_lower in msg_str_lower or prompt_text2_lower in msg_str_lower:
                    start_button_state_raw = str(self.btn_start_audit.cget('state')) if self.btn_start_audit else "unknown"
                    if start_button_state_raw == str(tk.DISABLED):
                        if self.btn_continue_after_login: self.btn_continue_after_login.config(state=tk.NORMAL)
        except queue.Empty:
            pass
        except Exception as e:
            error_msg_ula = f"ERROR in update_log_area: {e}\n{traceback.format_exc()}\n"
            print(error_msg_ula, file=sys.__stderr__)
            if self.log_area and self.log_area.winfo_exists():
                 self.log_area.insert(tk.END, error_msg_ula)
                 self.log_area.see(tk.END)
        finally:
            if self.root and self.root.winfo_exists():
                self.root.after(100, self.update_log_area)

    def run_audit_thread_target(self):
        self.log_queue.put("Audit thread starting...\n")
        if self.btn_stop_audit: self.btn_stop_audit.config(state=tk.NORMAL)

        original_stdout, original_stderr = sys.stdout, sys.stderr
        try:
            # Populate app_settings directly from GUI entries
            app_settings.MOODLE_LOGIN_URL = self.entry_moodle_url_var.get()
            app_settings.driver_path = self.entry_webdriver_path_var.get()
            app_settings.MAIN_OUTPUT_DIRECTORY_BASE = self.entry_output_base_dir_var.get()
            app_settings.VIRUSTOTAL_API_KEY = self.entry_vt_api_key_var.get().strip()
            app_settings.ENABLE_VIRUSTOTAL_CHECKS = self.var_enable_vt.get()
            app_settings.ENABLE_GOOGLE_SAFE_BROWSING_CHECKS = self.var_enable_gsb.get()
            app_settings.GOOGLE_SAFE_BROWSING_API_KEY = self.entry_gsb_api_key_var.get().strip()
            app_settings.ENABLE_METADEFENDER_CHECKS = self.var_enable_metadefender.get()
            app_settings.METADEFENDER_API_KEY = self.entry_metadefender_api_key_var.get().strip()

            try:
                max_pages_val = int(self.entry_max_pages_var.get())
                app_settings.MAX_PAGES_TO_CRAWL_PER_COURSE = max_pages_val if max_pages_val > 0 else 1
                if max_pages_val <= 0: self.log_queue.put("Warning: Max Pages must be > 0. Using 1.\n")
            except ValueError:
                default_max_p = getattr(app_settings, 'MAX_PAGES_TO_CRAWL_PER_COURSE', 1)
                self.log_queue.put(f"Warning: Invalid Max Pages. Using default {default_max_p}.\n")
                app_settings.MAX_PAGES_TO_CRAWL_PER_COURSE = default_max_p

            app_settings.ENABLE_LOCAL_FILE_SCANS = self.var_enable_local_scan.get()
            app_settings.FETCH_EXTERNAL_LINK_HTML = self.var_fetch_external_html.get()
            app_settings.ENABLE_QUICK_GRAB_CONTENT_PAGES = self.var_enable_quick_grab.get()

            try:
                timeout_val = int(self.entry_fetch_timeout_var.get())
                app_settings.EXTERNAL_LINK_HTML_FETCH_TIMEOUT = timeout_val if timeout_val > 0 else 1
                if timeout_val <= 0: self.log_queue.put("Warning: Fetch Timeout must be > 0. Using 1s.\n")
            except ValueError:
                default_t = getattr(app_settings, 'EXTERNAL_LINK_HTML_FETCH_TIMEOUT', 1)
                self.log_queue.put(f"Warning: Invalid Fetch Timeout. Using default {default_t}.\n")
                app_settings.EXTERNAL_LINK_HTML_FETCH_TIMEOUT = default_t

            if not all([app_settings.MOODLE_LOGIN_URL, app_settings.driver_path, app_settings.MAIN_OUTPUT_DIRECTORY_BASE]):
                error_msg_crit = "ERROR: Moodle URL, WebDriver, Output Dir required.\n"
                self.log_queue.put(error_msg_crit)
                messagebox.showerror("Config Error", error_msg_crit.replace("ERROR: ", "").strip())
                sys.stdout, sys.stderr = original_stdout, original_stderr
                self.log_queue.put(None)
                return

            self.log_queue.put(f"CONFIG_APP: Moodle URL: {app_settings.MOODLE_LOGIN_URL}\n")
            # ... other config logging ...
            app_settings.LOG_QUEUE = self.log_queue
            set_events_from_gui(self.audit_thread_continue_event, self.audit_thread_stop_event)

            class QueueIO:
                def __init__(self, q): self.queue = q
                def write(self, text):
                    if self.queue: self.queue.put(text)
                def flush(self): pass
            sys.stdout = QueueIO(self.log_queue)
            sys.stderr = QueueIO(self.log_queue)

            audit_lms_courses_fully() # From lms_auditor.core.auditor

        except Exception as e:
            error_msg_thread_setup = f"AUDIT THREAD ERROR: {e}\n{traceback.format_exc()}\n"
            is_redirected = 'original_stdout' in locals() and sys.stdout != original_stdout
            if is_redirected and self.log_queue: self.log_queue.put(error_msg_thread_setup)
            else: print(error_msg_thread_setup, file=original_stderr if 'original_stderr' in locals() else sys.__stderr__)
        finally:
            # ... (stdio restoration and sentinel as in original)
            final_debug_message = f"DEBUG_APP_THREAD_FINALLY: Audit thread 'finally'. Stop event: {self.audit_thread_stop_event.is_set()}\n"
            is_redirected_finally = 'original_stdout' in locals() and sys.stdout != original_stdout
            if is_redirected_finally and self.log_queue: self.log_queue.put(final_debug_message)
            else: print(final_debug_message, file=original_stdout if 'original_stdout' in locals() else sys.__stdout__)

            sys.stdout, sys.stderr = original_stdout, original_stderr
            self.log_queue.put(None) # Sentinel

    def start_audit(self):
        self.reset_ui_for_new_or_finished_audit(is_finished_run=False)
        if self.btn_start_audit and str(self.btn_start_audit.cget('state')) == str(tk.DISABLED) and \
           self.btn_start_audit.cget('text') == "Audit Running...":
            self.log_queue.put("INFO_APP: Audit is already considered running.\n")
            return

        if self.log_area: self.log_area.delete('1.0', tk.END)
        self.log_queue.put("---------------- NEW AUDIT RUN (main_app_window.py) ----------------\n")

        if self.btn_start_audit: self.btn_start_audit.config(state=tk.DISABLED, text="Audit Running...")
        if self.btn_stop_audit: self.btn_stop_audit.config(state=tk.DISABLED) # Thread will enable
        self.disable_config_fields()
        if self.root: self.root.update_idletasks()

        self.audit_thread_continue_event.clear()
        self.audit_thread_stop_event.clear()

        audit_thread = threading.Thread(target=self.run_audit_thread_target, daemon=True)
        audit_thread.start()

    def signal_continue_after_login(self):
        self.log_queue.put("GUI: 'Continue After Login' pressed.\n")
        self.audit_thread_continue_event.set()
        if self.btn_continue_after_login: self.btn_continue_after_login.config(state=tk.DISABLED)

    def signal_stop_audit(self):
        if messagebox.askyesno("Stop Audit", "Are you sure you want to stop the current audit process?"):
            self.log_queue.put("GUI: Stop Audit pressed. Signaling stop...\n")
            self.audit_thread_stop_event.set()
            if self.btn_stop_audit: self.btn_stop_audit.config(state=tk.DISABLED)

    def disable_config_fields(self):
        # References self.entry_moodle_url, etc.
        if hasattr(self, 'entry_moodle_url') and self.entry_moodle_url: self.entry_moodle_url.config(state=tk.DISABLED)
        if hasattr(self, 'entry_webdriver_path') and self.entry_webdriver_path: self.entry_webdriver_path.config(state=tk.DISABLED)
        if hasattr(self, 'btn_browse_webdriver') and self.btn_browse_webdriver: self.btn_browse_webdriver.config(state=tk.DISABLED)
        if hasattr(self, 'entry_output_base_dir') and self.entry_output_base_dir: self.entry_output_base_dir.config(state=tk.DISABLED)
        if hasattr(self, 'btn_browse_output') and self.btn_browse_output: self.btn_browse_output.config(state=tk.DISABLED)
        if hasattr(self, 'entry_vt_api_key') and self.entry_vt_api_key: self.entry_vt_api_key.config(state=tk.DISABLED)
        if hasattr(self, 'check_enable_vt') and self.check_enable_vt: self.check_enable_vt.config(state=tk.DISABLED)
        if hasattr(self, 'entry_max_pages') and self.entry_max_pages: self.entry_max_pages.config(state=tk.DISABLED)
        if hasattr(self, 'check_enable_local_scan') and self.check_enable_local_scan: self.check_enable_local_scan.config(state=tk.DISABLED)
        if hasattr(self, 'check_fetch_external_html') and self.check_fetch_external_html: self.check_fetch_external_html.config(state=tk.DISABLED)
        if hasattr(self, 'entry_fetch_timeout') and self.entry_fetch_timeout: self.entry_fetch_timeout.config(state=tk.DISABLED)
        if hasattr(self, 'check_enable_quick_grab') and self.check_enable_quick_grab: self.check_enable_quick_grab.config(state=tk.DISABLED)
        if hasattr(self, 'check_enable_gsb') and self.check_enable_gsb: self.check_enable_gsb.config(state=tk.DISABLED)
        if hasattr(self, 'entry_gsb_api_key') and self.entry_gsb_api_key: self.entry_gsb_api_key.config(state=tk.DISABLED)
        if hasattr(self, 'check_enable_metadefender') and self.check_enable_metadefender: self.check_enable_metadefender.config(state=tk.DISABLED)
        if hasattr(self, 'entry_metadefender_api_key') and self.entry_metadefender_api_key: self.entry_metadefender_api_key.config(state=tk.DISABLED)

    def enable_config_fields(self):
        # References self.entry_moodle_url, etc.
        if hasattr(self, 'entry_moodle_url') and self.entry_moodle_url: self.entry_moodle_url.config(state=tk.NORMAL)
        if hasattr(self, 'entry_webdriver_path') and self.entry_webdriver_path: self.entry_webdriver_path.config(state=tk.NORMAL)
        if hasattr(self, 'btn_browse_webdriver') and self.btn_browse_webdriver: self.btn_browse_webdriver.config(state=tk.NORMAL)
        if hasattr(self, 'entry_output_base_dir') and self.entry_output_base_dir: self.entry_output_base_dir.config(state=tk.NORMAL)
        if hasattr(self, 'btn_browse_output') and self.btn_browse_output: self.btn_browse_output.config(state=tk.NORMAL)
        if hasattr(self, 'entry_vt_api_key') and self.entry_vt_api_key: self.entry_vt_api_key.config(state=tk.NORMAL)
        if hasattr(self, 'check_enable_vt') and self.check_enable_vt: self.check_enable_vt.config(state=tk.NORMAL)
        if hasattr(self, 'entry_max_pages') and self.entry_max_pages: self.entry_max_pages.config(state=tk.NORMAL)
        if hasattr(self, 'check_enable_local_scan') and self.check_enable_local_scan: self.check_enable_local_scan.config(state=tk.NORMAL)
        if hasattr(self, 'check_fetch_external_html') and self.check_fetch_external_html: self.check_fetch_external_html.config(state=tk.NORMAL)
        if hasattr(self, 'entry_fetch_timeout') and self.entry_fetch_timeout: self.entry_fetch_timeout.config(state=tk.NORMAL)
        if hasattr(self, 'check_enable_quick_grab') and self.check_enable_quick_grab: self.check_enable_quick_grab.config(state=tk.NORMAL)
        if hasattr(self, 'check_enable_gsb') and self.check_enable_gsb: self.check_enable_gsb.config(state=tk.NORMAL)
        if hasattr(self, 'entry_gsb_api_key') and self.entry_gsb_api_key: self.entry_gsb_api_key.config(state=tk.NORMAL)
        if hasattr(self, 'check_enable_metadefender') and self.check_enable_metadefender: self.check_enable_metadefender.config(state=tk.NORMAL)
        if hasattr(self, 'entry_metadefender_api_key') and self.entry_metadefender_api_key: self.entry_metadefender_api_key.config(state=tk.NORMAL)
# The if __name__ == "__main__": block to launch this will be in the root main.py