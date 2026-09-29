# SkillLink Backend — Working Integrated Build

This is the merged backend, not a collection of test snippets.

## Stack
- Node.js 20+
- Express
- PostgreSQL / Supabase PostgreSQL
- bcryptjs
- JWT in HTTP-only cookie
- Helmet
- CORS
- Rate limiting

## Install
npm install

## Configure
Copy `.env.example` to `.env` and set:
- postgresql://postgres:masterpay@4652@db.qphofcllcuvwtliobgqz.supabase.co:5432/postgres
- SkL!2026_9xK7mP2vQ8rL5tN4zW6aC1sD
- https://skill-link-888.vercel.app
- CEO_PASSWORD

Never commit `.env`.

## Database
Run `database/schema.sql` once in the Supabase SQL Editor.

## Create first CEO
npm run seed:ceo

The seed script is intentionally the only place that accepts the initial CEO password from an environment variable.

## Start
npm start

Health:
GET /api/health

## Main API groups
/auth
/users
/packages
/courses
/referrals
/earnings
/withdrawals
/projects
/leads
/levels
/scores
/certificates
/notifications
/masterclasses
/company-settings
/disputes

## Important integration note
The frontend must call the API with credentials enabled, for example:
fetch(API_URL + "/api/auth/login", {
  method:"POST",
  credentials:"include",
  headers:{"Content-Type":"application/json"},
  body:JSON.stringify(data)
})

No production password, JWT secret, database URL, or service-role key belongs in `index.html`.

## Security behavior
- Server-side role checks
- Server-side record ownership checks for client/partner project communication
- Partner cannot self-assign projects
- Partner cannot create projects
- Minimum withdrawal ₹100
- Withdrawal balance deduction happens inside a PostgreSQL transaction
- Referral ownership can only be attached once
- CEO cannot be deactivated through the user-status endpoint
- Audit logging for important administrative actions
