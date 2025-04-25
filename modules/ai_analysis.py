import os
import logging
import json
import google.generativeai as genai # type: ignore
from google.generativeai.types import HarmCategory, HarmBlockThreshold # type: ignore

def analyze_with_gemini(report_data):
    """
    Use Google's Gemini API to analyze security findings and provide recommendations.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logging.warning("GEMINI_API_KEY not found in environment variables")
        return "AI analysis unavailable - No Gemini API key provided."
    
    try:
        # Configure the Gemini API
        genai.configure(api_key=api_key)
        
        # Set up the model
        generation_config = {
            "temperature": 0.2,
            "top_p": 0.8,
            "top_k": 40,
            "max_output_tokens": 2048,
        }
        
        safety_settings = {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
        }
        
        model = genai.GenerativeModel(
            model_name="gemini-1.0-pro",
            generation_config=generation_config,
            safety_settings=safety_settings
        )
        
        # Format the report data for the prompt
        report_summary = format_report_for_analysis(report_data)
        
        # Create the prompt
        prompt = f"""
        You are an experienced security researcher analyzing web application vulnerabilities. 
        Please provide a detailed security analysis of the following scan results:
        
        {report_summary}
        
        In your analysis, please include:
        1. A summary of the most critical vulnerabilities found
        2. An assessment of the overall security posture
        3. Detailed recommendations for fixing each vulnerability
        4. Prioritization of fixes (what should be addressed first)
        5. Additional security tests that should be considered
        
        Format your response in clear sections with bullet points where appropriate.
        """
        
        # Generate response from Gemini
        response = model.generate_content(prompt)
        
        if response and hasattr(response, 'text'):
            return response.text
        else:
            return "AI analysis completed but no response was generated."
            
    except Exception as e:
        logging.error(f"Error in Gemini AI analysis: {str(e)}")
        return f"Error performing AI analysis: {str(e)}"

def format_report_for_analysis(report_data):
    """
    Format the report data into a concise summary for the AI to analyze.
    """
    summary = f"Target: {report_data.get('target', 'Unknown')}\n\n"
    
    # Reconnaissance summary
    if 'recon' in report_data and report_data['recon']:
        summary += "RECONNAISSANCE FINDINGS:\n"
        recon_data = report_data['recon']
        
        if 'subdomains' in recon_data and recon_data['subdomains']:
            summary += f"- Found {len(recon_data['subdomains'])} subdomains\n"
        
        if 'shodan_data' in recon_data and recon_data['shodan_data']:
            if 'error' not in recon_data['shodan_data']:
                summary += "- Shodan data collected\n"
            else:
                summary += f"- Shodan error: {recon_data['shodan_data'].get('error', 'Unknown error')}\n"
        
        if 'dns_records' in recon_data and recon_data['dns_records']:
            summary += "- DNS records collected\n"
        
        if 'whois' in recon_data and recon_data['whois']:
            if 'error' not in recon_data['whois']:
                summary += "- WHOIS information collected\n"
    
    # Attack surface summary
    if 'attack_surface' in report_data and report_data['attack_surface']:
        summary += "\nATTACK SURFACE FINDINGS:\n"
        attack_data = report_data['attack_surface']
        
        if 'pages' in attack_data:
            summary += f"- Discovered {len(attack_data.get('pages', []))} pages\n"
        
        if 'forms' in attack_data:
            summary += f"- Found {len(attack_data.get('forms', []))} forms with user input\n"
        
        if 'endpoints' in attack_data:
            summary += f"- Identified {len(attack_data.get('endpoints', []))} API endpoints\n"
        
        if 'authentication_mechanisms' in attack_data:
            summary += f"- Detected {len(attack_data.get('authentication_mechanisms', []))} auth mechanisms\n"
    
    # Vulnerability scan summary
    if 'vulnerability_scan' in report_data and report_data['vulnerability_scan']:
        summary += "\nVULNERABILITY SCAN FINDINGS:\n"
        scan_data = report_data['vulnerability_scan']
        
        if 'security_headers' in scan_data:
            missing = scan_data.get('security_headers', {}).get('missing_headers', [])
            if missing:
                summary += f"- Missing security headers: {', '.join([h.get('header', '') for h in missing])}\n"
        
        if 'cors_config' in scan_data and scan_data.get('cors_config', {}).get('misconfigured'):
            summary += "- CORS misconfiguration detected\n"
        
        if 'fuzzing_results' in scan_data and isinstance(scan_data.get('fuzzing_results', []), list):
            potential_vulns = [r for r in scan_data.get('fuzzing_results', []) if r.get('potential_vulnerability')]
            if potential_vulns:
                summary += f"- Fuzzing found {len(potential_vulns)} potential vulnerabilities\n"
        
        if 'zap_scan' in scan_data and 'findings' in scan_data['zap_scan']:
            zap_findings = scan_data['zap_scan'].get('findings', [])
            high_risk = [f for f in zap_findings if f.get('risk') == 'High']
            medium_risk = [f for f in zap_findings if f.get('risk') == 'Medium']
            low_risk = [f for f in zap_findings if f.get('risk') == 'Low']
            
            if high_risk:
                summary += f"- ZAP scan: {len(high_risk)} high risk findings\n"
            if medium_risk:
                summary += f"- ZAP scan: {len(medium_risk)} medium risk findings\n"
            if low_risk:
                summary += f"- ZAP scan: {len(low_risk)} low risk findings\n"
    
    # Manual testing summary
    if 'manual_testing' in report_data and report_data['manual_testing']:
        summary += "\nMANUAL TESTING FINDINGS:\n"
        manual_data = report_data['manual_testing']
        
        test_type = manual_data.get('test_type', 'unknown')
        results = manual_data.get('results', {})
        
        if results.get('vulnerable', False):
            summary += f"- {test_type.upper()} vulnerability confirmed\n"
            if 'details' in results:
                summary += f"- {len(results.get('details', {}))} vulnerable endpoints/parameters found\n"
    
    # Advanced exploitation summary
    if 'advanced_exploitation' in report_data and report_data['advanced_exploitation']:
        summary += "\nADVANCED EXPLOITATION FINDINGS:\n"
        exploit_data = report_data['advanced_exploitation']
        
        if 'exploit_chain' in exploit_data:
            chain = exploit_data.get('exploit_chain', [])
            summary += f"- Tested exploitation chain: {' → '.join(chain)}\n"
        
        if exploit_data.get('success', False):
            summary += f"- Exploitation successful with {exploit_data.get('final_impact', 'Unknown')} impact\n"
            
            if 'chain_results' in exploit_data:
                successful_steps = [step for step in exploit_data.get('chain_results', []) 
                                  if step.get('success', False)]
                summary += f"- {len(successful_steps)}/{len(exploit_data.get('chain_results', []))} chain steps successful\n"
    
    return summary
