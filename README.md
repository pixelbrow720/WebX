# AI-Powered Web Security Reconnaissance Tool (WebX)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)
[![Documentation](https://img.shields.io/badge/docs-USAGE.md-orange.svg)](USAGE.md)

A Web Security Reconnaissance Tool powered by artificial intelligence (AI) to assist in website security testing, featuring a dark-themed UI.

## Key Features

- **Reconnaissance**: Gather information about targets, including subdomains, infrastructure, and technology identification.
- **Attack Surface Mapping**: Identify potential entry points and vulnerability areas in target applications.
- **Vulnerability Scanning**: Automated scanning to identify common security weaknesses and misconfigurations.
- **Manual Testing**: Tools for manual testing against OWASP Top 10 vulnerabilities and other security issues.
- **Advanced Exploitation**: Combine multiple vulnerabilities to demonstrate real-world attack scenarios and their impact.
- **Reporting**: Comprehensive reports with findings, evidence, and remediation recommendations enhanced by AI analysis.

## Getting Started

### Prerequisites

- Python 3.11 or newer
- Pip (Python Package Manager)
- Internet connection (for downloading dependencies)

### Installation

1. Clone this repository to your local machine:
   ```
   git clone https://github.com/pixelbrow720/WebX.git
   cd WebX
   ```

2. Create a Python virtual environment (optional but recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # For Linux/Mac
   venv\Scripts\activate     # For Windows
   ```

3. Install all required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up environment variables:
   - To use AI analysis, obtain a Gemini API key from [Google AI Studio](https://makersuite.google.com/)
   ```
   export GEMINI_API_KEY="your_api_key_here"  # For Linux/Mac
   set GEMINI_API_KEY=your_api_key_here       # For Windows (Command Prompt)
   $env:GEMINI_API_KEY="your_api_key_here"    # For Windows (PowerShell)
   ```

### Running the Application

1. Run the Flask server:
   ```
   python main.py
   ```
   Or use Gunicorn for deployment:
   ```
   gunicorn --bind 0.0.0.0:5000 main:app
   ```

2. Open your browser and access the application at [http://localhost:5000](http://localhost:5000)

## Usage

For detailed usage instructions, please see [USAGE.md](USAGE.md).

## Project Structure

- `main.py`: Main application entry point
- `app.py`: Flask application configuration and route definitions
- `modules/`: Directory containing functional application modules
  - `reconnaissance.py`: Module for reconnaissance and information gathering
  - `attack_surface.py`: Module for attack surface mapping
  - `vulnerability_scan.py`: Module for vulnerability scanning
  - `manual_testing.py`: Module for manual testing
  - `advanced_exploitation.py`: Module for advanced exploitation
  - `reporting.py`: Module for report generation
  - `ai_analysis.py`: Module for AI analysis using Gemini
- `static/`: Static assets including CSS and JavaScript
- `templates/`: HTML templates for the user interface
- `reports/`: Directory where reports are stored

## Important Notes

- This tool is intended for educational purposes and legitimate testing only.
- Always obtain permission before conducting security testing on any system.
- Using this tool against systems without proper authorization may be illegal.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Contact

[github.com/pixelbrow720](https://github.com/pixelbrow720)
