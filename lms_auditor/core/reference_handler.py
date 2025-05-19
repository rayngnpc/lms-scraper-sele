# reference_manager.py
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import re
import json
from lms_auditor.config import app_settings

class ReferenceManager:
    def __init__(self):
        self.metadata_cache = {}

    def _fetch_html(self, url):
        try:
            headers = {'User-Agent': app_settings.USER_AGENT_FOR_REQUESTS}
            response = requests.get(url, timeout=app_settings.EXTERNAL_LINK_HTML_FETCH_TIMEOUT, headers=headers, allow_redirects=True)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"  [RefManager] WARN: Could not fetch HTML for {url} to extract metadata: {e}")
            return None

    def extract_metadata(self, url, html_content=None):
        """Extract academic reference metadata from webpage"""
        if url in self.metadata_cache:
            return self.metadata_cache[url]

        if html_content is None and app_settings.FETCH_EXTERNAL_LINK_HTML:
            # print(f"  [RefManager] Fetching HTML for metadata: {url[:80]}...") # Optional: for debugging
            html_content = self._fetch_html(url)

        metadata = {
            'url': url,
            'access_date': datetime.now().strftime("%Y-%m-%d"),
            'title': url.split('/')[-1].split('?')[0] or url, # Basic title from URL if no HTML
            'authors': [],
            'publication_date': '',
            'publisher': '',
            'site_name': ''
        }
        
        parsed_url = requests.utils.urlparse(url)
        metadata['site_name'] = parsed_url.netloc


        if not html_content:
            self.metadata_cache[url] = metadata
            return metadata

        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract from meta tags
        meta_mappings = {
            'title': ['citation_title', 'og:title', 'twitter:title', 'dc.title'],
            'authors': ['citation_author', 'author', 'dc.creator', 'article:author'],
            'publication_date': ['citation_publication_date', 'publication_date', 'dc.date', 'article:published_time', 'datePublished'],
            'publisher': ['citation_publisher', 'publisher', 'dc.publisher', 'og:site_name'],
            'site_name': ['og:site_name', 'application-name']
        }

        if soup.title and soup.title.string:
             metadata['title'] = soup.title.string.strip()

        for field, meta_names in meta_mappings.items():
            found_meta = False
            for name in meta_names:
                # Check for <meta name="...">
                meta_tag = soup.find('meta', {'name': name.lower()})
                if meta_tag and meta_tag.get('content'):
                    content = meta_tag['content'].strip()
                    if field == 'authors':
                        # Split multiple authors if separated by common delimiters
                        authors_list = re.split(r'\s*;\s*|\s*,\s*', content)
                        for auth in authors_list:
                            if auth and auth.lower() != metadata['site_name'].lower() and auth not in metadata['authors']: # Avoid adding site name as author
                                metadata['authors'].append(auth)
                    elif field == 'title' and content: # Ensure title is not empty
                        metadata[field] = content
                        found_meta = True; break
                    elif field != 'authors' and content:
                         metadata[field] = content
                         found_meta = True; break
                
                # Check for <meta property="..."> (common for OG tags)
                meta_tag_prop = soup.find('meta', {'property': name.lower()})
                if meta_tag_prop and meta_tag_prop.get('content'):
                    content = meta_tag_prop['content'].strip()
                    if field == 'authors':
                        authors_list = re.split(r'\s*;\s*|\s*,\s*', content)
                        for auth in authors_list:
                             if auth and auth.lower() != metadata['site_name'].lower() and auth not in metadata['authors']:
                                metadata['authors'].append(auth)
                    elif field == 'title' and content:
                        metadata[field] = content
                        found_meta = True; break
                    elif field != 'authors' and content:
                         metadata[field] = content
                         found_meta = True; break
            if found_meta and field == 'title': # Prioritize meta title
                 continue


        # Fallback to structured data (JSON-LD)
        schema_org_scripts = soup.find_all('script', {'type': 'application/ld+json'})
        for schema_org in schema_org_scripts:
            if schema_org.string:
                try:
                    schema_data = json.loads(schema_org.string)
                    items_to_check = []
                    if isinstance(schema_data, list): items_to_check.extend(schema_data)
                    else: items_to_check.append(schema_data)

                    for item_data in items_to_check:
                        if not isinstance(item_data, dict): continue
                        item_type = item_data.get('@type', '')
                        if isinstance(item_type, list): item_type = item_type[0] # Take first type if list

                        if item_type in ['Article', 'ScholarlyArticle', 'NewsArticle', 'WebPage', 'Report', 'Book']:
                            if not metadata['title'] or metadata['title'] == url.split('/')[-1].split('?')[0]: # Only override if title is basic
                                metadata['title'] = item_data.get('headline', item_data.get('name', metadata['title']))
                            
                            if not metadata['authors']:
                                author_data = item_data.get('author')
                                if author_data:
                                    if isinstance(author_data, list):
                                        for auth_entry in author_data:
                                            if isinstance(auth_entry, dict) and auth_entry.get('name') and auth_entry['name'] not in metadata['authors']:
                                                metadata['authors'].append(auth_entry['name'])
                                            elif isinstance(auth_entry, str) and auth_entry not in metadata['authors']:
                                                 metadata['authors'].append(auth_entry)
                                    elif isinstance(author_data, dict) and author_data.get('name') and author_data['name'] not in metadata['authors']:
                                        metadata['authors'].append(author_data['name'])
                                    elif isinstance(author_data, str) and author_data not in metadata['authors']:
                                         metadata['authors'].append(author_data)


                            if not metadata['publication_date']:
                                metadata['publication_date'] = item_data.get('datePublished', item_data.get('dateCreated', metadata['publication_date']))
                            
                            if not metadata['publisher']:
                                publisher_data = item_data.get('publisher')
                                if isinstance(publisher_data, dict) and publisher_data.get('name'):
                                    metadata['publisher'] = publisher_data['name']
                                elif isinstance(publisher_data, str):
                                     metadata['publisher'] = publisher_data

                            if item_data.get('isPartOf') and isinstance(item_data['isPartOf'], dict) and item_data['isPartOf'].get('name') and not metadata['publisher']:
                                metadata['publisher'] = item_data['isPartOf']['name'] # e.g. journal name

                            # Break if we found a good schema type, assuming it's the most relevant
                            if metadata['title'] and metadata['title'] != url.split('/')[-1].split('?')[0]:
                                break 
                    if metadata['title'] and metadata['title'] != url.split('/')[-1].split('?')[0]:
                        break
                except json.JSONDecodeError:
                    pass
        
        # Clean up authors - remove duplicates and filter out site name again
        if metadata['authors']:
            seen_authors = set()
            unique_authors = []
            for author in metadata['authors']:
                author_clean = author.strip()
                if author_clean and author_clean.lower() != metadata['site_name'].lower() and author_clean.lower() not in seen_authors:
                    unique_authors.append(author_clean)
                    seen_authors.add(author_clean.lower())
            metadata['authors'] = unique_authors


        # If title is still the URL, try prominent H1
        if (not metadata['title'] or metadata['title'] == url.split('/')[-1].split('?')[0] or metadata['title'] == url) and soup.h1:
            metadata['title'] = soup.h1.get_text(strip=True)

        metadata['title'] = re.sub(r'\s+', ' ', metadata['title']).strip() if metadata['title'] else "No Title Found"


        self.metadata_cache[url] = metadata
        return metadata

    def format_apa7_reference(self, metadata):
        """Format metadata into APA7 citation"""
        authors_str = ""
        authors = metadata.get('authors', [])
        if authors:
            if len(authors) == 1:
                authors_str = authors[0]
            elif len(authors) == 2:
                authors_str = f"{authors[0]} & {authors[1]}"
            elif len(authors) <= 20: # List all authors up to 20
                authors_str = ", ".join(authors[:-1]) + f", & {authors[-1]}"
            else: # More than 20 authors
                authors_str = ", ".join(authors[:19]) + f", ... {authors[-1]}"
        else: # No authors, use title first if site name not distinct
            site_name = metadata.get('site_name', '')
            # If publisher is same as site_name or site_name is generic, don't use it as author
            if not metadata.get('publisher') or metadata['publisher'].lower() == site_name.lower() or any(generic in site_name.lower() for generic in ['.com', '.org', '.net']):
                authors_str = "" # Title will come first
            else:
                authors_str = site_name # Organization as author

        pub_date = metadata.get('publication_date', '')
        year_str = "(n.d.)"
        if pub_date:
            match = re.search(r'(\d{4})', str(pub_date)) # Extract year
            if match:
                year_str = f"({match.group(1)})"
            else: # If year not found but date exists, try to include it
                try: # Attempt to parse and reformat
                    dt_obj = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                    year_str = f"({dt_obj.strftime('%Y, %B %d')})"
                except ValueError:
                    year_str = f"({pub_date})" # Fallback to raw date if complex

        title = metadata.get('title', "Untitled Document")
        # For webpages, italicize the title of the webpage itself
        # If it's part of a larger work (e.g., article in a journal), that larger work is italicized.
        # Here, we assume 'title' is the specific page title.
        title_italicized = f"<i>{title}</i>"

        publisher_or_site = metadata.get('publisher') or metadata.get('site_name')
        
        # APA7: Author, A. A. (Year). Title of work. Site Name. URL
        # If Author and Site Name are the same, omit Site Name.
        # If no author, Title of work. (Year). Site Name. URL
        
        reference_parts = []
        if authors_str:
            reference_parts.append(f"{authors_str}.")
        
        reference_parts.append(f"{year_str}.")

        if not authors_str: # Title moves to author position
            reference_parts.append(f"{title_italicized}.")
            if publisher_or_site:
                 reference_parts.append(f"{publisher_or_site}.")
        else: # Author exists, title in normal position
            reference_parts.append(f"{title_italicized}.")
            # Only add site name if it's different from author and adds value
            if publisher_or_site and publisher_or_site.lower() != authors_str.lower().replace('.', ''):
                 reference_parts.append(f"{publisher_or_site}.")


        reference_parts.append(f"Retrieved {metadata.get('access_date', 'unknown date')} from {metadata.get('url', '#')}")

        return " ".join(part for part in reference_parts if part.strip() != '.')