# lms_auditor/core/report_services.py
from jinja2 import Environment, FileSystemLoader, select_autoescape
import os
import csv
import json
import re
from urllib.parse import urlparse
from datetime import datetime
from lms_auditor.config import app_settings # For app_settings.ENABLE_LOCAL_FILE_SCANS in template context
from jinja2 import Environment, FileSystemLoader, select_autoescape

# --- Jinja2 Custom Filters ---
def url_basename_filter(value):
    """Jinja2 filter to get a displayable basename from a URL."""
    if not value or value == '#' or not isinstance(value, str):
        return "N/A"
    try:
        path = urlparse(value).path
        basename = os.path.basename(path)
        if basename:
            return basename
        # If no basename (e.g., directory URL), try to get last segment
        segments = [s for s in path.split('/') if s]
        if segments:
            return segments[-1]
        return "Link" # Fallback
    except Exception:
        return "N/A"

def format_timestamp_filter(value):
    """Jinja2 filter to format a Unix timestamp into a readable date-time string."""
    if not value:
        return "N/A"
    try:
        return datetime.fromtimestamp(int(value)).strftime('%Y-%m-%d %H:%M UTC')
    except (ValueError, TypeError, OSError): # OSError for very large/small timestamps
        return str(value) # Fallback to string representation if parsing fails

def truncate_filter(value, length=50, suffix='...'):
    """Jinja2 filter to truncate a string."""
    if not isinstance(value, str):
        return value
    if len(value) <= length:
        return value
    return value[:length-len(suffix)] + suffix

# --- CSV and JSON Functions (largely unchanged from your link_analysis.py) ---
def generate_course_audit_summary_csv(course_audit_data_list, report_filepath):
    if not course_audit_data_list:
        print("No course audit data for CSV report.")
        return
    os.makedirs(os.path.dirname(report_filepath), exist_ok=True)

    fieldnames = ['Course Name', 'Course URL', 'Pages Crawled',
                  'Internal Pages Linked', 'Internal Files Linked',
                  'Int. PDFs', 'Int. Docs', 'Int. PPTs', 'Int. Sheets',
                  'Int. Images', 'Int. Audio', 'Int. Video Files',
                  'Int. Archives', 'Int. Plugin/Other Files',
                  'External Links Total',
                  'Ext. Video Platforms', 'Ext. Video Files (Direct)',
                  'Ext. PDFs', 'Ext. Docs', 'Ext. PPTs', 'Ext. Sheets',
                  'Ext. Images', 'Ext. Audio', 'Ext. Archives',
                  'Ext. Other Files', 'Ext. Other Page Links'
                 ] # Keep this consistent with your original `link_analysis.py`
    try:
        with open(report_filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for course in course_audit_data_list:
                counts = course.get('link_and_file_counts', {})
                int_pages = counts.get('lms_course_page', 0) + counts.get('lms_other_page', 0) + counts.get('uni_other_page', 0)
                int_files = sum(v for k,v in counts.items() if k.startswith(('lms_file_', 'uni_file_')))
                ext_total = sum(v for k,v in counts.items() if k.startswith('external_'))
                writer.writerow({
                    'Course Name': course.get('course_name', 'N/A'),
                    'Course URL': course.get('course_url', 'N/A'),
                    'Pages Crawled': course.get('pages_crawled_in_course', 0),
                    'Internal Pages Linked': int_pages,
                    'Internal Files Linked': int_files,
                    'Int. PDFs': counts.get('lms_file_pdf', 0) + counts.get('uni_file_pdf', 0),
                    'Int. Docs': counts.get('lms_file_doc', 0) + counts.get('uni_file_doc', 0),
                    'Int. PPTs': counts.get('lms_file_ppt', 0) + counts.get('uni_file_ppt', 0),
                    # ... (fill in all other fields as per your original CSV structure) ...
                    'Int. Sheets': counts.get('lms_file_sheet', 0) + counts.get('uni_file_sheet', 0),
                    'Int. Images': counts.get('lms_file_image', 0) + counts.get('uni_file_image', 0),
                    'Int. Audio': counts.get('lms_file_audio', 0) + counts.get('uni_file_audio', 0),
                    'Int. Video Files': counts.get('lms_file_video_direct', 0) + counts.get('uni_file_video_direct', 0),
                    'Int. Archives': counts.get('lms_file_archive', 0) + counts.get('uni_file_archive', 0),
                    'Int. Plugin/Other Files': (counts.get('lms_file_plugin', 0) + counts.get('lms_file_other', 0) +
                                               counts.get('uni_file_plugin', 0) + counts.get('uni_file_other', 0)),
                    'External Links Total': ext_total,
                    'Ext. Video Platforms': counts.get('external_video_platform', 0),
                    'Ext. Video Files (Direct)': counts.get('external_file_video_direct', 0),
                    'Ext. PDFs': counts.get('external_file_pdf',0) + counts.get('external_file_pdf_viewer',0),
                    'Ext. Docs': counts.get('external_file_doc',0) + counts.get('external_file_doc_viewer',0),
                    'Ext. PPTs': counts.get('external_file_ppt',0) + counts.get('external_file_ppt_viewer',0),
                    'Ext. Sheets': counts.get('external_file_sheet',0),
                    'Ext. Images': counts.get('external_file_image',0),
                    'Ext. Audio': counts.get('external_file_audio',0),
                    'Ext. Archives': counts.get('external_file_archive',0),
                    'Ext. Other Files': counts.get('external_file_other',0),
                    'Ext. Other Page Links': counts.get('external_other', 0) + counts.get('external_document_viewer', 0)
                })
        print(f"Generated course audit summary CSV: {report_filepath}")
    except Exception as e:
        print(f"ERROR generating CSV {report_filepath}: {e}")
        import traceback
        traceback.print_exc()

def save_data_to_json_file(data_to_save, full_filepath):
    try:
        os.makedirs(os.path.dirname(full_filepath), exist_ok=True)
        with open(full_filepath, "w", encoding="utf-8") as f:
            json.dump(data_to_save, f, indent=2, ensure_ascii=False)
        print(f"Saved data to: {full_filepath}")
    except Exception as e:
        print(f"ERROR saving JSON '{full_filepath}': {e}")
        import traceback
        traceback.print_exc()

# --- HTML Report Generation using Jinja2 ---
def generate_detailed_course_report(course_data, output_dir, template_dir): # Added template_dir
    course_name_sanitized = re.sub(r'[<>:"/\\|?*]', '_', course_data.get('course_name', 'Unknown_Course'))
    course_name_sanitized = "".join(c for c in course_name_sanitized if c.isalnum() or c in (' ', '_', '-')).strip()[:100]
    if not course_name_sanitized: course_name_sanitized = "Course_Report"
    report_filename = f"{course_name_sanitized}_detailed_report.html"
    report_filepath = os.path.join(output_dir, report_filename)
    
    print(f"Generating HTML report for '{course_data.get('course_name', 'N/A')}' at: {report_filepath}")
    try:
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True, lstrip_blocks=True
        )
        env.filters['url_basename'] = url_basename_filter
        env.filters['format_timestamp'] = format_timestamp_filter
        env.filters['truncate'] = truncate_filter

        template = env.get_template("detailed_course_report_template.html")
        context = {
            "course": course_data,
            "generation_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "app_settings": app_settings, # Make app_settings available to template if needed
            "author_name": getattr(app_settings, 'REPORT_AUTHOR_NAME', "Ray Nguyen")
        }
        html_content = template.render(context)
        
        os.makedirs(output_dir, exist_ok=True)
        with open(report_filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Successfully generated detailed HTML report: {report_filepath}")
        return report_filename # Return filename for main index
    except Exception as e:
        print(f"Error generating detailed HTML report for {course_data.get('course_name', 'N/A')} using Jinja2: {e}")
        import traceback; traceback.print_exc()
        return None

def generate_main_index_html(all_courses_summary_data, output_dir, template_dir, run_id_str):
    index_filepath = os.path.join(output_dir, "index.html")
    print(f"Generating main audit index HTML: {index_filepath}")
    try:
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True, lstrip_blocks=True
        )
        env.filters['url_basename'] = url_basename_filter # Register if used in main_index_template

        template = env.get_template("main_index_template.html")
        context = {
            "run_id": run_id_str,
            "courses": all_courses_summary_data, # List of course summary dicts
            "generation_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "total_courses_processed": len(all_courses_summary_data),
            "author_name": getattr(app_settings, 'REPORT_AUTHOR_NAME', "Ray Nguyen")
        }
        html_content = template.render(context)
        with open(index_filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"Successfully generated main audit index HTML: {index_filepath}")
    except Exception as e:
        print(f"Error generating main index HTML using Jinja2: {e}")
        import traceback; traceback.print_exc()
