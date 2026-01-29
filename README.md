# Secure Incident Portal 🔐

A secure web-based incident reporting system built with **Flask** that allows employees to submit encrypted incident reports and enables authorized analysts/admins to decrypt and verify them.

The system enforces strong security using:
- Multi-Factor Authentication (TOTP / Google Authenticator)
- AES encryption for report confidentiality
- RSA digital signatures for data integrity and authenticity
- Role-based access control with audit logging

---

## ✨ Features

- 🔐 Secure user registration and login
- 📱 Two-Factor Authentication (TOTP via Google Authenticator)
- 🔑 MFA-protected password reset
- 🧑‍💼 Role based access:
  - **Employee** – submit encrypted incident reports
  - **Analyst/Admin** – decrypt and verify reports
  - **Admin** – manage users and view audit logs
- 🛡️ AES encryption of report content
- ✍️ RSA digital signature verification to detect tampering
- 🖼️ Optional image evidence upload
- 📜 Audit trail for logins, report submission and unauthorized access
- 🚫 Custom 403 Forbidden page for blocked access

---

## 🏗️ Tech Stack

- Python 3
- Flask
- Flask-Login
- Flask-SQLAlchemy
- SQLite
- PyOTP (TOTP based MFA)
- Cryptography (AES + RSA)
- Bootstrap 5 (UI)

---

## 📂 Project Structure