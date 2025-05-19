# lms_auditor/gui/ui_helpers.py
import tkinter as tk
from tkinter import ttk, filedialog, font as tkFont
import queue # For the log_queue if initialize_fonts uses it

# --- Dark Theme Color Palette (Refined) ---
COLOR_PRIMARY_BG = "#2B2B2B"       # Main window background - very dark gray
COLOR_FRAME_BG = "#3C3F41"         # Frame background - slightly lighter dark gray (like IntelliJ Darcula)
COLOR_TEXT_ON_DARK = "#BBBBBB"     # Light gray for general text
COLOR_LABEL_TEXT_DARK = "#A9B7C6"  # Soft blue-gray for labels (Darcula-like)
COLOR_BUTTON = "#4A4A70"           # Muted dark purple/blue for buttons
COLOR_BUTTON_ACTIVE = "#5F5F90"    # Lighter shade for button hover/active
COLOR_BUTTON_TEXT = "#FFFFFF"       # White text on buttons
COLOR_ACCENT_HIGHLIGHT = "#6A87C5"  # A pleasant blue for selected items/focus
COLOR_DISABLED_FG = "#777777"      # Medium gray for disabled text
COLOR_DISABLED_BG = "#333333"      # Darker gray for disabled button background
COLOR_ENTRY_BG = "#313335"          # Background for Entry widgets (Darcula-like)
COLOR_ENTRY_FG = COLOR_TEXT_ON_DARK # Text color for Entry widgets
COLOR_LOG_BG = "#2B2B2B"            # Match primary background or slightly different dark
COLOR_LOG_FG = "#A9B7C6"            # Soft blue-gray for log text (Darcula-like)
COLOR_SEPARATOR = "#555555"

# Define COLOR_WIDGET_BG for use in ttk styles (matches frame background)
COLOR_WIDGET_BG = COLOR_FRAME_BG
COLOR_TEXT_FG = COLOR_TEXT_ON_DARK # General text fg, same as COLOR_TEXT_ON_DARK
COLOR_BUTTON_BG = COLOR_BUTTON
COLOR_BUTTON_FG = COLOR_BUTTON_TEXT
COLOR_BUTTON_ACTIVE_BG = COLOR_BUTTON_ACTIVE
COLOR_DISABLED_WIDGET_BG = COLOR_DISABLED_BG


# --- Font Definitions ---
FONT_GENERAL_FAMILY = "Arial"
FONT_GENERAL = None
FONT_BUTTON = None
FONT_LABEL_FRAME_TITLE = None
FONT_LOG = ("Consolas", 10)


def initialize_fonts(log_q=None): # Optional log_q parameter
    """Initializes font families after the root window is created."""
    global FONT_GENERAL_FAMILY, FONT_GENERAL, FONT_BUTTON, FONT_LABEL_FRAME_TITLE

    font_families_to_try = ["Segoe UI", "Tahoma", "Verdana", "DejaVu Sans", "Helvetica", "Arial"]
    found_family = None
    for family_name in font_families_to_try:
        try:
            tk.font.Font(family=family_name, size=10)
            found_family = family_name
            break
        except tk.TclError:
            pass
    FONT_GENERAL_FAMILY = found_family if found_family else "Arial"

    FONT_GENERAL = (FONT_GENERAL_FAMILY, 10)
    FONT_BUTTON = (FONT_GENERAL_FAMILY, 10, "bold")
    FONT_LABEL_FRAME_TITLE = (FONT_GENERAL_FAMILY, 11, "bold")
    if log_q: log_q.put(f"DEBUG_UI_HELPERS: Fonts initialized. Using: {FONT_GENERAL_FAMILY}\n")


def apply_ttk_styles(log_q=None): # Optional log_q parameter
    """Applies custom styles to TTK widgets for a dark theme."""
    if FONT_GENERAL is None: initialize_fonts(log_q) # Pass log_q along

    style = ttk.Style()
    try:
        style.theme_use('clam')
    except tk.TclError:
        print("Warning: 'clam' theme not available, styling might be limited.")
        if log_q: log_q.put("WARN_UI_HELPERS: 'clam' theme not available.\n")


    style.configure(".",
                    background=COLOR_FRAME_BG,
                    foreground=COLOR_TEXT_ON_DARK,
                    font=FONT_GENERAL,
                    borderwidth=0,
                    relief=tk.FLAT)
    style.configure("TFrame", background=COLOR_FRAME_BG) # Explicit for TFrame

    # Custom style for an outer frame if you want it to match the primary window background
    style.configure("Outer.TFrame", background=COLOR_PRIMARY_BG)

    style.configure("TLabelFrame",
                    background=COLOR_FRAME_BG,
                    bordercolor=COLOR_SEPARATOR, # Border of the LabelFrame
                    relief=tk.SOLID,             # Or tk.GROOVE, tk.RIDGE based on preference
                    borderwidth=1)
    style.configure("TLabelFrame.Label",               # The text label of the LabelFrame
                    background=COLOR_FRAME_BG,         # Background of the label part
                    foreground=COLOR_LABEL_TEXT_DARK,  # Text color of the label
                    font=FONT_LABEL_FRAME_TITLE)

    style.configure("TButton",
                    font=FONT_BUTTON,
                    padding=(10, 5),
                    background=COLOR_BUTTON,
                    foreground=COLOR_BUTTON_TEXT,
                    relief=tk.RAISED,
                    borderwidth=1,
                    focuscolor=COLOR_ACCENT_HIGHLIGHT) # For focus ring, theme-dependent
    style.map("TButton",
              background=[('active', COLOR_BUTTON_ACTIVE), ('disabled', COLOR_DISABLED_BG)],
              foreground=[('disabled', COLOR_DISABLED_FG)],
              relief=[('pressed', tk.SUNKEN), ('!pressed', tk.RAISED)],
              bordercolor=[('active', COLOR_BUTTON_ACTIVE)]) # Border color on hover/active

    style.configure("TLabel",
                    background=COLOR_FRAME_BG,
                    foreground=COLOR_LABEL_TEXT_DARK, # Using the specific label text color
                    font=FONT_GENERAL)

    style.configure("TEntry",
                    font=FONT_GENERAL,
                    padding=4,
                    selectbackground=COLOR_ACCENT_HIGHLIGHT, # Background of selected text
                    selectforeground=COLOR_BUTTON_TEXT)     # Foreground of selected text
    style.map("TEntry",
              fieldbackground=[('disabled', COLOR_DISABLED_BG),
                               ('!disabled', COLOR_ENTRY_BG)], # Background of the text area
              foreground=[('disabled', COLOR_DISABLED_FG),
                          ('!disabled', COLOR_ENTRY_FG)],     # Text color
              # Border color on focus can be tricky with ttk themes
              # relief=[('focus', tk.SOLID), ('!focus', tk.FLAT)] # Subtle relief change might work
             )
    style.configure("TCheckbutton",
                    background=COLOR_FRAME_BG,
                    foreground=COLOR_LABEL_TEXT_DARK, # Text next to checkbutton
                    font=FONT_GENERAL,
                    indicatordiameter=14, # Size of the check indicator
                    padding=(5,3))
    style.map("TCheckbutton",
              background=[('active', COLOR_FRAME_BG)], # BG when mouse is over
              foreground=[('disabled', COLOR_DISABLED_FG)],
              # Styling the indicator (the box itself)
              indicatorbackground=[('selected', COLOR_ACCENT_HIGHLIGHT), # Box bg when checked
                                   ('!selected', COLOR_ENTRY_BG)],    # Box bg when unchecked
              indicatorforeground=[('selected', COLOR_BUTTON_TEXT)]) # Color of the checkmark

    style.configure("TSeparator", background=COLOR_SEPARATOR)

    style.configure("Vertical.TScrollbar",
                    gripcount=0,
                    background=COLOR_BUTTON,           # Scrollbar slider color
                    bordercolor=COLOR_FRAME_BG,        # Border around the scrollbar
                    troughcolor=COLOR_ENTRY_BG,        # Background of the scrollbar track
                    arrowcolor=COLOR_BUTTON_TEXT)      # Color of arrows (if visible)
    style.map("Vertical.TScrollbar",
              background=[('active', COLOR_BUTTON_ACTIVE)])
def browse_webdriver_path(entry_var): # Takes the StringVar as an argument
    filename = filedialog.askopenfilename(title="Select WebDriver")
    if filename and entry_var: entry_var.set(filename)

def browse_output_dir(entry_var): # Takes the StringVar as an argument
    directory = filedialog.askdirectory(title="Select Base Output Directory")
    if directory and entry_var: entry_var.set(directory)

