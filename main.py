# main.py (Project Root)
import tkinter as tk
import sys
import os

# Add the project root to sys.path to allow imports from lms_auditor package
# This is useful if you run main.py directly from the project root.
# If lms_auditor is installed as a package (e.g. via pip setup.py develop), this might not be strictly necessary.
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Now we can import from our package
from lms_auditor.gui.main_app_window import LMSAuditorApp

if __name__ == "__main__":
    root = tk.Tk()
    app = LMSAuditorApp(root)
    root.mainloop()