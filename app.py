import os
import logging
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
import urllib.parse
from werkzeug.middleware.proxy_fix import ProxyFix

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "development_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Add template context processor for current date/time
@app.context_processor
def inject_now():
    from datetime import datetime
    return {'now': datetime.now()}

# Import modules
from modules.reconnaissance import perform_reconnaissance
from modules.attack_surface import map_attack_surface
from modules.vulnerability_scan import perform_vulnerability_scan
from modules.manual_testing import perform_manual_testing
from modules.advanced_exploitation import perform_advanced_exploitation
from modules.reporting import save_report, get_reports
from modules.ai_analysis import analyze_with_gemini

# Create reports directory if it doesn't exist
os.makedirs("reports", exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/reconnaissance', methods=['GET', 'POST'])
def reconnaissance():
    if request.method == 'POST':
        target = request.form.get('target')
        scan_type = request.form.get('scan_type')
        shodan_enabled = 'shodan_enabled' in request.form
        subdomains_enabled = 'subdomains_enabled' in request.form
        
        if not target:
            flash('Target domain is required', 'error')
            return redirect(url_for('reconnaissance'))
            
        results = perform_reconnaissance(
            target=target, 
            scan_type=scan_type, 
            shodan_enabled=shodan_enabled,
            subdomains_enabled=subdomains_enabled
        )
        
        # Store results in session for later reporting
        session['recon_results'] = results
        
        return render_template('reconnaissance.html', results=results, target=target)
    
    return render_template('reconnaissance.html')

@app.route('/attack_surface', methods=['GET', 'POST'])
def attack_surface():
    if request.method == 'POST':
        target = request.form.get('target')
        crawl_depth = int(request.form.get('crawl_depth', 2))
        endpoints_only = 'endpoints_only' in request.form
        
        if not target:
            flash('Target URL is required', 'error')
            return redirect(url_for('attack_surface'))
            
        results = map_attack_surface(
            target=target,
            crawl_depth=crawl_depth,
            endpoints_only=endpoints_only
        )
        
        # Store results in session for later reporting
        session['attack_surface_results'] = results
        
        return render_template('attack_surface.html', results=results, target=target)
    
    return render_template('attack_surface.html')

@app.route('/vulnerability_scan', methods=['GET', 'POST'])
def vulnerability_scan():
    if request.method == 'POST':
        target = request.form.get('target')
        scan_type = request.form.get('scan_type', 'quick')
        zap_enabled = 'zap_enabled' in request.form
        fuzzing_enabled = 'fuzzing_enabled' in request.form
        
        if not target:
            flash('Target URL is required', 'error')
            return redirect(url_for('vulnerability_scan'))
            
        results = perform_vulnerability_scan(
            target=target,
            scan_type=scan_type,
            zap_enabled=zap_enabled,
            fuzzing_enabled=fuzzing_enabled
        )
        
        # Store results in session for later reporting
        session['vulnerability_scan_results'] = results
        
        return render_template('vulnerability_scan.html', results=results, target=target)
    
    return render_template('vulnerability_scan.html')

@app.route('/manual_testing', methods=['GET', 'POST'])
def manual_testing():
    if request.method == 'POST':
        target = request.form.get('target')
        test_type = request.form.get('test_type')
        payload = request.form.get('payload')
        
        if not target or not test_type:
            flash('Target URL and test type are required', 'error')
            return redirect(url_for('manual_testing'))
            
        results = perform_manual_testing(
            target=target,
            test_type=test_type,
            payload=payload
        )
        
        # Store results in session for later reporting
        session['manual_testing_results'] = results
        
        return render_template('manual_testing.html', results=results, target=target, test_type=test_type)
    
    return render_template('manual_testing.html')

@app.route('/advanced_exploitation', methods=['GET', 'POST'])
def advanced_exploitation():
    if request.method == 'POST':
        target = request.form.get('target')
        exploit_chain = request.form.getlist('exploit_chain')
        custom_payload = request.form.get('custom_payload')
        
        if not target or not exploit_chain:
            flash('Target URL and at least one exploit chain item are required', 'error')
            return redirect(url_for('advanced_exploitation'))
            
        results = perform_advanced_exploitation(
            target=target,
            exploit_chain=exploit_chain,
            custom_payload=custom_payload
        )
        
        # Store results in session for later reporting
        session['advanced_exploitation_results'] = results
        
        return render_template('advanced_exploitation.html', results=results, target=target)
    
    return render_template('advanced_exploitation.html')

@app.route('/reports', methods=['GET', 'POST'])
def reports():
    if request.method == 'POST':
        target = request.form.get('target')
        report_title = request.form.get('report_title')
        
        # Gather all results from session
        report_data = {
            'target': target,
            'title': report_title,
            'recon': session.get('recon_results', {}),
            'attack_surface': session.get('attack_surface_results', {}),
            'vulnerability_scan': session.get('vulnerability_scan_results', {}),
            'manual_testing': session.get('manual_testing_results', {}),
            'advanced_exploitation': session.get('advanced_exploitation_results', {})
        }
        
        # Use Gemini for AI analysis if requested
        if 'ai_analysis' in request.form:
            ai_analysis = analyze_with_gemini(report_data)
            report_data['ai_analysis'] = ai_analysis
        
        # Save report
        report_file = save_report(report_data)
        flash(f'Report saved as {report_file}', 'success')
        
        # Clear session data
        for key in ['recon_results', 'attack_surface_results', 'vulnerability_scan_results', 
                    'manual_testing_results', 'advanced_exploitation_results']:
            if key in session:
                session.pop(key)
        
        return redirect(url_for('reports'))
    
    # Get list of existing reports
    available_reports = get_reports()
    
    return render_template('reports.html', reports=available_reports)

@app.route('/reports/<filename>', methods=['GET'])
def view_report(filename):
    try:
        import json
        with open(f'reports/{filename}', 'r') as f:
            report_data = json.load(f)
        return jsonify(report_data)
    except Exception as e:
        logging.error(f"Error loading report: {str(e)}")
        flash(f'Error loading report: {str(e)}', 'error')
        return redirect(url_for('reports'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
