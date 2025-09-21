# Manpower Platform MVP

A comprehensive web platform for connecting contractors, agencies, and individual workers. Built with Flask, modern JavaScript, and a focus on security and scalability.

## 📖 Overview

A modern, secure workforce management platform that facilitates connections between agencies, contractors, and individual workers. This MVP includes robust authentication, user verification, contract management, messaging, analytics, and a responsive frontend.

## 🚀 Features Overview

### Authentication & Security

- User registration with email verification (token-based, persistent)
- Secure password reset via email link (token-based, persistent)
- Passwords hashed with Werkzeug (scrypt)
- Session-based authentication with secure, HTTP-only cookies
- Rate limiting on all critical endpoints (Flask-Limiter)
- CSP and security headers for all frontend pages
- MFA (Multi-Factor Authentication) support (demo)

### User Management

- User roles: agency, contractor, individual
- Profile data stored in `data/registrations.json` (canonical)
- Email verification and verification badges
- Manual and automated user verification (admin endpoint)
- Profile completion, rating, and review system
- File uploads (with validation and storage in `uploads/`)

### Contract & Application System

- Create, list, and filter contracts by user role
- Apply to contracts (individuals)
- Claim and approve contracts (agencies, contractors)
- Escrow and payment simulation endpoints
- All contract data stored in `data/contracts.json`

### Messaging & Notifications

- User-to-user messaging system (stored in `data/messages.json`)
- Email notifications for verification and password reset
- System notifications (stored in `data/notifications.json`)
- Real-time notification simulation

### Analytics & Dashboard

- Role-based dashboards for all user types
- Analytics endpoints for contracts, earnings, reviews, and more
- Marketplace and advanced search endpoints

### Frontend

- Responsive HTML5/CSS3 with modern, dark-themed UI
- Vanilla JS for authentication, forms, dashboard, and modals
- CSP-compliant: all inline JS moved to external files
- Custom modals for sign-in, sign-up, and password reset
- SVG icons and optimized assets

### Data & Persistence

- All data stored in JSON files with file locking (filelock)
- Persistent token storage for password resets and verification
- Logging to `logs/` directory for API, errors, and security events
- Automated backup and restore for all data files

## 🛠️ Project Structure

- `app.py` — Main Flask backend, all API endpoints and business logic
- `static/` — JS, CSS, SVG assets (CSP-compliant)
- `templates/` — HTML templates for all pages and dashboards
- `data/` — All persistent JSON data (users, contracts, applications, messages, notifications, verifications)
- `logs/` — Application and error logs
- `uploads/` — File upload storage
- `requirements.txt` — All Python dependencies

Backend Utilities:

- `config.py` — Application configuration and security settings
- `logger.py` — Centralized logging system
- `validation.py` — Input validation framework
- `validators.py` — Specific validation rules
- `security.py` — Security utilities
- `email_templates.py` — Email template system

## 🧑‍💻 User Flows

### Registration & Verification

- Users register with email, password, and role (agency, contractor, individual)
- Email verification link sent (token stored in `verification_tokens.json`)
- User must verify email before signing in
- Admin can manually verify users via API

### Sign-In & Session

- Secure sign-in with email and password
- Session and user role stored in Flask session and secure cookie
- Rate limiting to prevent brute-force

### Password Reset

- Users can request a password reset link via email
- Reset tokens are stored in `reset_tokens.json` (expire after 1 hour)
- Passwords are updated securely and immediately

### Contracts & Applications

- Contractors/agencies can create and manage contracts
- Individuals can apply to contracts
- Agencies/contractors can claim and approve contracts
- All actions logged and persisted

### Messaging & Notifications Flow

- Users can send messages to each other (role-based permissions)
- System notifications for key events (contract updates, verification, etc.)
- Email notifications for critical actions

### Dashboard & Analytics

- Each user role has a custom dashboard (HTML templates)
- Analytics endpoints for contracts, reviews, earnings, etc.
- Marketplace and advanced search for users/contracts

### File Uploads

- Users can upload files (profile docs, contracts, etc.)
- Files are validated and stored in `uploads/`
- File info is linked to user profiles

### Payments (Simulated)

- Endpoints for creating and processing payments (demo only)
- Payment records stored in `payments.json`
- Email notifications for payment events

---

## ⚙️ How to Run

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure your `.env` (see below)
4. Run: `python app.py`
5. Open: [http://localhost:5000](http://localhost:5000)

### Example .env

```ini
SECRET_KEY=your_secret_key_here
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_email_password
SESSION_LIFETIME=86400
CORS_ORIGIN=*
```

---

## 🧩 Troubleshooting & Developer Notes

- If sign-in fails, check your email and password, and ensure `email_verified` is true in `data/registrations.json`.
- Use the password reset flow if you forget your password.
- Check backend logs for `[DEBUG] Received signin:` to see what the server receives.
- For manual fixes, edit `data/registrations.json` and restart the server. If you have an old `registrations.json` in the repository root, migrate it to `data/registrations.json` or remove it to prevent duplication (see migration steps below).
- All data is stored in the `data/` directory for easy backup and migration.
- All endpoints are rate-limited for security.
- All frontend JS is CSP-compliant (no inline scripts).

---

## 📈 Next Steps / TODO

- Integrate a real database (PostgreSQL/MongoDB)
- Add real-time chat and notifications (WebSockets)
- Payment gateway integration
- Mobile app support
- AI-powered contract matching and analytics
- Advanced admin dashboard and reporting

### Migration Notes

If you have a `registrations.json` at the repository root, it may be an older copy. The application now reads and writes `data/registrations.json` by default. To migrate:

1. Stop the server
2. If a root `registrations.json` exists, copy or move it to `data/registrations.json` (or merge manually)
3. Start the server and verify users appear in the dashboard
4. Optionally archive or delete the root `registrations.json` to avoid future confusion

---

This MVP is ready for further development and real-world testing. For more details, see the code and comments in each file described below.
