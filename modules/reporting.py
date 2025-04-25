import os
import json
import logging
import datetime
import base64

def save_report(report_data):
    """
    Save vulnerability scanning results to a JSON file.
    """
    if not report_data:
        return {'error': 'No report data provided'}
    
    # Create reports directory if it doesn't exist
    os.makedirs('reports', exist_ok=True)
    
    # Generate filename based on target and timestamp
    target = report_data.get('target', 'unknown')
    if '://' in target:
        target = target.split('://')[1]
    target = target.replace('/', '_').replace(':', '_')
    
    timestamp = datetime.datetime.now().isoformat()
    filename = f"report_{target}_{timestamp}.json"
    file_path = os.path.join('reports', filename)
    
    # Process any screenshots (convert to base64)
    if 'screenshots' in report_data:
        for i, screenshot in enumerate(report_data['screenshots']):
            if os.path.exists(screenshot):
                try:
                    with open(screenshot, 'rb') as img_file:
                        img_data = base64.b64encode(img_file.read()).decode('utf-8')
                        report_data['screenshots'][i] = {
                            'filename': os.path.basename(screenshot),
                            'data': img_data
                        }
                except Exception as e:
                    logging.error(f"Error processing screenshot {screenshot}: {str(e)}")
                    report_data['screenshots'][i] = {
                        'filename': os.path.basename(screenshot),
                        'error': str(e)
                    }
    
    # Add metadata
    report_data['generated_at'] = datetime.datetime.now().isoformat()
    report_data['filename'] = filename
    
    # Write report to file
    try:
        with open(file_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        
        logging.info(f"Report saved to {file_path}")
        return filename
    except Exception as e:
        logging.error(f"Error saving report: {str(e)}")
        return {'error': str(e)}

def get_reports():
    """
    Get a list of available reports.
    """
    reports = []
    
    # Create reports directory if it doesn't exist
    os.makedirs('reports', exist_ok=True)
    
    try:
        for filename in os.listdir('reports'):
            if filename.endswith('.json'):
                file_path = os.path.join('reports', filename)
                try:
                    with open(file_path, 'r') as f:
                        report_data = json.load(f)
                    
                    # Extract basic info for the report listing
                    reports.append({
                        'filename': filename,
                        'target': report_data.get('target', 'Unknown'),
                        'timestamp': report_data.get('generated_at', ''),
                        'title': report_data.get('title', filename)
                    })
                except Exception as e:
                    logging.error(f"Error reading report {filename}: {str(e)}")
                    reports.append({
                        'filename': filename,
                        'error': str(e)
                    })
    except Exception as e:
        logging.error(f"Error listing reports: {str(e)}")
        return {'error': str(e)}
    
    # Sort by timestamp (newest first)
    reports.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return reports

def get_report_by_filename(filename):
    """
    Get a specific report by filename.
    """
    file_path = os.path.join('reports', filename)
    
    if not os.path.exists(file_path):
        return {'error': 'Report not found'}
    
    try:
        with open(file_path, 'r') as f:
            report_data = json.load(f)
        return report_data
    except Exception as e:
        logging.error(f"Error reading report {filename}: {str(e)}")
        return {'error': str(e)}

def generate_html_report(report_data):
    """
    Generate an HTML version of the JSON report.
    This is a simple implementation - in a real scenario, you'd use a template engine.
    """
    if not report_data:
        return '<p>No report data available</p>'
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report: {report_data.get('target', 'Unknown')}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #121212; color: #e0e0e0; }}
            h1, h2, h3 {{ color: #bb86fc; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .section {{ margin-bottom: 30px; border: 1px solid #333; padding: 15px; border-radius: 5px; background-color: #1e1e1e; }}
            .vulnerability {{ margin-bottom: 15px; padding: 10px; border-left: 4px solid #bb86fc; }}
            .high {{ border-left-color: #cf6679; }}
            .medium {{ border-left-color: #ffab40; }}
            .low {{ border-left-color: #03dac6; }}
            .info {{ border-left-color: #3700b3; }}
            .metadata {{ font-style: italic; font-size: 0.9em; color: #9e9e9e; }}
            pre {{ background-color: #2d2d2d; padding: 10px; border-radius: 5px; overflow-x: auto; color: #e0e0e0; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #333; }}
            th {{ background-color: #2d2d2d; }}
            img {{ max-width: 100%; height: auto; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Security Scan Report</h1>
            <div class="section">
                <h2>Metadata</h2>
                <table>
                    <tr><th>Target</th><td>{report_data.get('target', 'Unknown')}</td></tr>
                    <tr><th>Report Title</th><td>{report_data.get('title', 'Security Scan')}</td></tr>
                    <tr><th>Generated At</th><td>{report_data.get('generated_at', 'Unknown')}</td></tr>
                </table>
            </div>
    """
    
    # Add reconnaissance results if available
    if 'recon' in report_data and report_data['recon']:
        html += f"""
            <div class="section">
                <h2>Reconnaissance Results</h2>
                <pre>{json.dumps(report_data['recon'], indent=4)}</pre>
            </div>
        """
    
    # Add attack surface mapping if available
    if 'attack_surface' in report_data and report_data['attack_surface']:
        html += f"""
            <div class="section">
                <h2>Attack Surface Mapping</h2>
                <pre>{json.dumps(report_data['attack_surface'], indent=4)}</pre>
            </div>
        """
    
    # Add vulnerability scan results if available
    if 'vulnerability_scan' in report_data and report_data['vulnerability_scan']:
        html += f"""
            <div class="section">
                <h2>Vulnerability Scan Results</h2>
                <pre>{json.dumps(report_data['vulnerability_scan'], indent=4)}</pre>
            </div>
        """
    
    # Add manual testing results if available
    if 'manual_testing' in report_data and report_data['manual_testing']:
        html += f"""
            <div class="section">
                <h2>Manual Testing Results</h2>
                <pre>{json.dumps(report_data['manual_testing'], indent=4)}</pre>
            </div>
        """
    
    # Add advanced exploitation results if available
    if 'advanced_exploitation' in report_data and report_data['advanced_exploitation']:
        html += f"""
            <div class="section">
                <h2>Advanced Exploitation Results</h2>
                <pre>{json.dumps(report_data['advanced_exploitation'], indent=4)}</pre>
            </div>
        """
    
    # Add AI analysis if available
    if 'ai_analysis' in report_data and report_data['ai_analysis']:
        html += f"""
            <div class="section">
                <h2>AI Analysis</h2>
                <pre>{report_data['ai_analysis']}</pre>
            </div>
        """
    
    # Close HTML
    html += """
        </div>
    </body>
    </html>
    """
    
    return html
