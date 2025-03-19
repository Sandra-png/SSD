This project is a Flask-based web application that provides secure user authentication
and file management capabilities, including user registration, password reset, file upload,
and file download, following best security practices.

# Running the Application
1. Run the flask application using "python app.py".
2. Access the application through the provided runtime weblink.


# Features
## User Authentication
- Secure user registration with password hashing
- Log in with JWT authentication tokens
- Secure password reset mechanisms

## File Management
- Secure file upload with access control
- Secure file download with authentication checks

## Security Measures
- SQL injection prevention with parameterized queries
- Cross-Site Scripting (XSS) protection with input validation
- API authentication with JWT-based access tokens
- Secure storage of API keys and tokens
- Docker setup for isolated and controlled execution environment

## Testing the Application
Tests were conducted by running Bandit. Penetration attacks were done using OWASP Zap, and scanned for:
  - Broken access control
  - SQL Injections
  - Hardcoding
  - Weak cryptographic keys
  - Design flaws
  - Outdated components
  - ETC...

While the tests did uncover some issues, all were commented on in the exam but not all were mitigated.
