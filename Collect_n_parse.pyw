import os
import zipfile
import gzip
import shutil
import xml.etree.ElementTree as ET
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

def decompress_zip_files(zip_files, output_dir):
    """
    Decompresses a list of .zip files into the specified output directory.
    
    :param zip_files: List of paths to .zip files.
    :param output_dir: Directory to extract files to.
    """
    for zip_file in zip_files:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall(output_dir)

def decompress_gz_files(gz_files, output_dir):
    """
    Decompresses a list of .gz files into the specified output directory.
    
    :param gz_files: List of paths to .gz files.
    :param output_dir: Directory to extract files to.
    """
    for gz_file in gz_files:
        with gzip.open(gz_file, 'rb') as f_in:
            output_path = os.path.join(output_dir, os.path.basename(gz_file).replace('.gz', ''))
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

def get_text_or_none(element, subelement):
    """
    Helper function to get text from an XML element. Returns None if the subelement is not found.
    
    :param element: The XML element.
    :param subelement: The subelement to find within the XML element.
    :return: The text of the subelement, or None if not found.
    """
    if element is not None:
        found_element = element.find(subelement)
        return found_element.text if found_element is not None else None
    return None

def parse_dmarc_xml(xml_file):
    """
    Parses a DMARC .xml file and returns a dictionary with relevant information.
    
    :param xml_file: Path to the .xml file.
    :return: Parsed data in a dictionary format.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    report_metadata = root.find('report_metadata')
    policy_published = root.find('policy_published')
    records = root.findall('record')
    
    parsed_data = {
        'report_metadata': {
            'org_name': get_text_or_none(report_metadata, 'org_name'),
            'email': get_text_or_none(report_metadata, 'email'),
            'report_id': get_text_or_none(report_metadata, 'report_id'),
            'date_range': {
                'begin': get_text_or_none(report_metadata.find('date_range'), 'begin') if report_metadata is not None else None,
                'end': get_text_or_none(report_metadata.find('date_range'), 'end') if report_metadata is not None else None,
            }
        },
        'policy_published': {
            'domain': get_text_or_none(policy_published, 'domain'),
            'adkim': get_text_or_none(policy_published, 'adkim'),
            'aspf': get_text_or_none(policy_published, 'aspf'),
            'p': get_text_or_none(policy_published, 'p'),
            'sp': get_text_or_none(policy_published, 'sp'),
            'pct': get_text_or_none(policy_published, 'pct'),
        },
        'records': []
    }
    
    for record in records:
        row_element = record.find('row')
        identifiers_element = record.find('identifiers')
        auth_results_element = record.find('auth_results')
        
        row = {
            'source_ip': get_text_or_none(row_element, 'source_ip'),
            'count': get_text_or_none(row_element, 'count'),
            'policy_evaluated': {
                'disposition': get_text_or_none(row_element.find('policy_evaluated'), 'disposition') if row_element is not None else None,
                'dkim': get_text_or_none(row_element.find('policy_evaluated'), 'dkim') if row_element is not None else None,
                'spf': get_text_or_none(row_element.find('policy_evaluated'), 'spf') if row_element is not None else None,
            },
            'identifiers': {
                'header_from': get_text_or_none(identifiers_element, 'header_from'),
            },
            'auth_results': {
                'dkim': get_text_or_none(auth_results_element.find('dkim'), 'domain') if auth_results_element is not None else None,
                'spf': get_text_or_none(auth_results_element.find('spf'), 'domain') if auth_results_element is not None else None,
            }
        }
        parsed_data['records'].append(row)
    
    return parsed_data

def process_dmarc_reports_from_directory(directory, output_dir):
    """
    Processes multiple DMARC reports from a directory containing .zip and .gz files
    and converts them to a human-readable format.
    
    :param directory: Directory to search for .zip and .gz files.
    :param output_dir: Directory to extract files to and read .xml files from.
    """
    zip_files = []
    gz_files = []

    # Search for .zip and .gz files in the specified directory
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.zip'):
                zip_files.append(os.path.join(root, file))
            elif file.endswith('.gz'):
                gz_files.append(os.path.join(root, file))
    
    # Step 1: Decompress all zip files
    decompress_zip_files(zip_files, output_dir)
    
    # Step 2: Decompress all gz files
    decompress_gz_files(gz_files, output_dir)
    
    # Step 3: Process each decompressed .xml file
    all_reports = []
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".xml"):
                xml_file_path = os.path.join(root, file)
                report = parse_dmarc_xml(xml_file_path)
                all_reports.append(report)
    
    return all_reports

def save_reports_to_csv(reports, csv_file):
    """
    Saves parsed DMARC reports to a CSV file.
    
    :param reports: List of parsed DMARC reports.
    :param csv_file: Path to the CSV file to save the data.
    """
    rows = []
    for report in reports:
        metadata = report['report_metadata']
        policy = report['policy_published']
        for record in report['records']:
            row = {
                'org_name': metadata['org_name'],
                'email': metadata['email'],
                'report_id': metadata['report_id'],
                'date_range_begin': metadata['date_range']['begin'],
                'date_range_end': metadata['date_range']['end'],
                'domain': policy['domain'],
                'adkim': policy['adkim'],
                'aspf': policy['aspf'],
                'policy_p': policy['p'],
                'policy_sp': policy['sp'],
                'policy_pct': policy['pct'],
                'source_ip': record['source_ip'],
                'count': record['count'],
                'disposition': record['policy_evaluated']['disposition'],
                'dkim': record['policy_evaluated']['dkim'],
                'spf': record['policy_evaluated']['spf'],
                'header_from': record['identifiers']['header_from'],
                'auth_results_dkim': record['auth_results']['dkim'],
                'auth_results_spf': record['auth_results']['spf'],
            }
            rows.append(row)
    
    df = pd.DataFrame(rows)
    df.to_csv(csv_file, index=False)

def read_csv_and_display_chart(csv_file):
    """
    Reads the CSV file and displays a chart based on the data.
    
    :param csv_file: Path to the CSV file to read the data from.
    """
    df = pd.read_csv(csv_file)
    
    # Example: Display a chart of the top 20 source IPs by count
    ip_counts = df.groupby('source_ip')['count'].sum().nlargest(20)
    
    plt.figure(figsize=(10, 6))
    ip_counts.plot(kind='bar')
    plt.title('Top 20 Source IPs by Count in DMARC Report')
    plt.xlabel('Source IP')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()
    
    
def cleanup_extracted_files(output_dir):
    """
    Deletes all .xml files in the specified directory.
    
    :param output_dir: Directory to clean up.
    """
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".xml"):
                os.remove(os.path.join(root, file))

now = datetime.now()
currentdate = now.strftime("%Y-%m-%d %H-%M-%S")

# Example usage:
directory = 'C:/Users/%USERNAME%/Downloads/'  # Directory to search for .zip and .gz files
output_dir = 'C:/Users/%USERNAME%/Downloads/'
csv_file = 'C:/Users/%USERNAME%/Downloads/dmarc_reports'+currentdate+'.csv'

try: 
    reports = process_dmarc_reports_from_directory(directory, output_dir)
    save_reports_to_csv(reports, csv_file)
    read_csv_and_display_chart(csv_file)
    
finally:
    cleanup_extracted_files(output_dir)
