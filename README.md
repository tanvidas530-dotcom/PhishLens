PhishLens 🔐

A Browser-Based Scam Detector

PhishLens is a web-based cybersecurity project that analyzes URLs for suspicious patterns and provides an explainable risk assessment.

Features

- URL risk scoring from 0 to 100
- Low, Medium and High risk categories
- Detection of suspicious URL patterns
- Explanations for triggered warning indicators
- Interactive browser-based dashboard
- Demo URLs for testing
- Recent scan history within the browser session
- Input validation and automated tests

Technology Stack

- Frontend: HTML, CSS, JavaScript
- Backend: Python, Flask
- Testing: pytest
- Version Control: Git and GitHub

How It Works

1. The user enters a URL into the dashboard.
2. JavaScript sends the URL to the Flask API.
3. Python validates and analyzes its structure.
4. Configured detection rules assign risk points.
5. The application returns a score, risk category and explanations.
6. The dashboard displays the results.

Run Locally

1. Clone the repository

git clone YOUR_REPOSITORY_URL
cd PhishLens

2. Create a virtual environment

py -m venv venv

3. Activate it on Windows

.\venv\Scripts\Activate.ps1

4. Install dependencies

py -m pip install -r requirements.txt

5. Start the application

py app.py

Open http://127.0.0.1:5000 in your browser.

Run Tests

py -m pip install pytest
py -m pytest -v

Limitations

PhishLens uses heuristic URL analysis. Its score is not a probability of phishing and does not establish whether a website is safe or malicious.

The current version does not independently verify website reputation or inspect the destination website's content.

A low score does not guarantee safety, and legitimate URLs can trigger warnings.

Future Improvements

- Improved domain and lookalike detection
- Optional threat-intelligence integration
- More comprehensive automated tests
- Enhanced reporting and visualization
- Deployment to a hosting platform

Disclaimer

This project is intended for educational and defensive cybersecurity purposes. Analyze URLs without opening suspicious destinations. Do not submit private URLs containing authentication tokens or sensitive information to external services.

Author

Developed as a student cybersecurity and web development project.