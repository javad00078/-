# Deployment

## PostgreSQL
Create a database, set DATABASE_URL, then run `npm --prefix backend exec prisma migrate deploy`.

## Backend
`npm --prefix backend run build` then `npm --prefix backend start`.

## Frontend
Set `VITE_API_URL` to the public API URL and run `npm --prefix frontend run build`. Upload `frontend/dist` to static hosting.

Security: use HTTPS, COOKIE_SECURE=true, strong JWT secret, change all seed passwords, restrict CORS, never upload `.env`.
