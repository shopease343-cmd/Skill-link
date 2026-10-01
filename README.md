# SkillLink Full-Stack Platform — V3

This package keeps the existing SkillLink V2 visual frontend as its base and adds a production-oriented backend foundation.

## Stack
- Frontend: one `public/index.html` with inline HTML/CSS/JavaScript
- Backend: Node.js + Express
- Database: PostgreSQL
- Authentication: bcrypt + JWT in HttpOnly cookie + server-side session table
- RBAC: CEO / ADMIN / PARTNER / CLIENT
- Security: Helmet, rate limiting, validation, secure upload filtering, immutable audit log
- Financial: transactional earnings ledger + withdrawal workflow

## Important integration rule
This migration is **additive**. It does not DROP users, packages, courses, projects, referrals or levels. For an existing production database, run the migration only after comparing it with the existing schema and resolving any existing-table differences. No existing credentials are included in this package.

## Setup
1. Copy `.env.example` to `.env`.
2. Set a strong `DATABASE_URL`.
3. Set a random `JWT_SECRET` with at least 32 characters.
4. Set `COOKIE_SECURE=true` behind HTTPS.
5. Run:
   `npm install`
6. Apply:
   `psql "$DATABASE_URL" -f db/001_foundation.sql`
7. Start:
   `npm start`

## Authentication
There is exactly one public login page. The browser does not choose a role. The server loads the user's role from the database and the dashboard is rendered from the authenticated session.

Do not seed or publish real passwords in source code. Create the initial CEO through a secure deployment/bootstrap process using environment variables or a one-time admin provisioning script.

## Financial rules
- Partner/Admin withdrawal minimum: ₹100.
- Withdrawal availability is checked server-side.
- Withdrawal requests use a database transaction.
- CEO is the only role allowed to approve/reject/mark paid.
- Ledger entries have a unique `(user_id, source_type, source_id)` constraint to prevent duplicate earnings.
- Rejected/failed withdrawals restore reserved balance transactionally.
- Paid withdrawals increase withdrawn amount transactionally.

## Refund policy
The schema includes the 45-day / ₹10,000 SkillLink-generated earnings eligibility workflow. It intentionally does not silently auto-approve a refund; CEO verification remains required.

## File uploads
Allowed types:
- PNG
- JPEG
- WEBP
- PDF

Maximum file size: 8 MB per upload. Stored filenames are random UUID-based names. Executable file types are rejected.

## Remaining production integration
For an existing live SkillLink installation, connect this package to the current database/repository and map any existing table names before migration. Payment gateway integration, cloud object storage, email/SMS delivery, and external meeting providers require their actual production credentials/configuration; no fake integrations are included.
