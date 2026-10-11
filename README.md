#  SecureDeps Cloud
### Full-Stack Python Project Security Analyzer

SecureDeps Cloud is a web-based security analysis tool that helps developers identify potential security issues in Python projects before deployment. Users can upload a ZIP archive of their project and receive a report with findings, explanations, and recommendations.

##  Features

- **User Authentication** — Account registration and login.
- **ZIP Project Upload** — Upload Python projects for security analysis.
- **Archive Validation** — Validate uploaded archives before analysis.
- **Project Structure Analysis** — Inspect project files and structure for potential concerns.
- **Python Code Security Analysis** — Analyze Python source code for selected security patterns.
- **Dependency Vulnerability Analysis** — Check supported, pinned dependencies against vulnerability data from the OSV service.
- **Security Reports** — View findings and recommendations in a readable report.
- **Scan History** — Access previous scan results associated with your account.
- **Web Dashboard** — Manage project scans and review results.

##  Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application and analysis logic |
| Flask | Web framework |
| Flask-SQLAlchemy | Database integration |
| Flask-Login | User authentication and session management |
| Flask-WTF | CSRF protection |
| Flask-Limiter | Rate limiting |
| Argon2 | Password hashing |
| HTML and CSS | User interface |
| JavaScript | Interactive frontend features |
| OSV API | Dependency vulnerability information |
| SQLite | Local development database |

##  Project Structure

```text
securedeps-cloud/
├── analyzers/
│   ├── structure.py
│   ├── code_security.py
│   └── dependencies.py
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── upload.js
│       ├── charts.js
│       ├── dashboard.js
│       └── auth.js
├── templates/
│   ├── login.html
│   ├── signup.html
│   ├── dashboard.html
│   ├── history.html
│   ├── report.html
│   └── security_activity.html
├── tests/
├── instance/
├── app.py
├── auth.py
├── archive_handler.py
├── extensions.py
├── models.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

*The tree represents the intended project layout. Adjust filenames to match the files currently present in your repository.*

##  Requirements

- Python 3.12 or a compatible supported Python version
- Git
- A GitHub account
- Internet access for dependency vulnerability checks

##  Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/harshhhhh22/Secureds-cloud.git
cd Secureds-cloud
```

### 2. Create a virtual environment

**Windows:**

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root. Set a strong, random secret key and any other required settings.

Example:

```env
SECRET_KEY=replace-with-a-long-random-secret
DATABASE_URL=sqlite:///securedeps.db
COOKIE_SECURE=false
```

**Important:** Replace the example secret with a newly generated secret. Never commit your real `.env` file, credentials, or API tokens to GitHub. Use `COOKIE_SECURE=false` only for local HTTP development; use secure cookies when deployed over HTTPS.

### 5. Start the application

```bash
python app.py
```

Open the application in your browser:

**http://127.0.0.1:5000**

Register an account, sign in, and upload a supported ZIP archive to begin a scan.

##  How It Works

1. **Upload:** The user selects a ZIP archive containing a project.
2. **Validate:** The application checks the archive against configured safety limits.
3. **Analyze:** The available analyzers inspect the project structure, Python code, and supported dependency files.
4. **Report:** Findings are combined into a report with severity information and recommendations where available.
5. **Review:** The user can open saved reports and review scan history.

##  Security Considerations

- Passwords are hashed rather than stored as plaintext.
- Authentication is required for protected scanning and report routes.
- CSRF protection helps defend form submissions against cross-site request forgery.
- Rate limiting helps reduce automated abuse.
- ZIP validation helps guard against unsafe archive contents and excessive extraction sizes.
- Environment variables keep application secrets out of source code.
- Scan reports are associated with their owning accounts.

This project is a development and educational security tool. Its findings are not a guarantee that a project is secure, and its analyzers may produce false positives or miss vulnerabilities. Review important findings manually.

##  Current Scope and Limitations

The current implementation includes project-structure checks, selected Python code security checks, and dependency checks for supported requirements files and exactly pinned package versions.

Documentation and CI/CD analysis are not yet implemented. Dependency results depend on the supported file formats, available vulnerability data, and network access to OSV. Results should not be treated as a complete security audit.

##  Running Tests

If the project has a configured pytest test suite, activate your virtual environment and run:

```bash
python -m pytest
```

Review the test results before making a release or deploying the application.

##  Future Improvements

- Documentation and configuration security checks
- CI/CD workflow analysis
- Additional dependency file formats
- Exportable PDF reports
- Interactive dashboard charts
- Docker support and deployment guidance
- Continuous integration with automated tests

##  Author

**Harshvardhan Devkar**

GitHub: [@harshhhhh22](https://github.com/harshhhhh22)

##  License

No license has been specified yet. Add a license file if you intend to define how others may use, modify, and distribute this project.

---

**SecureDeps Cloud — Helping developers identify potential security risks before deployment.**
