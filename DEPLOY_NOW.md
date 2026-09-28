# Publish checklist

1. Create a Supabase project.
2. Open SQL Editor and run `database/schema.sql`.
3. Create a backend deployment (Render/Railway/etc.).
4. Add environment variables from `.env.example`.
5. Run `npm install`.
6. Run `npm run seed:ceo` once.
7. Start with `npm start`.
8. Set the Vercel frontend's API URL to the deployed backend URL.
9. Frontend requests must use `credentials: "include"`.

Do not put DATABASE_URL, JWT_SECRET or any service-role key into Vercel's frontend source.
