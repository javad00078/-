# VANGUARD RP — LSPD MANAGEMENT
Full-stack LSPD personnel-management system.

Stack: React + TypeScript + Vite + Tailwind, Express + TypeScript, PostgreSQL + Prisma, Argon2, JWT cookie auth.

Features: authentication, password reset records, ranks, coins, activity submission/Dispatch verification, divisions/requests, announcements, playtime, online state, officer directory, rankings, audit logs, permissions.

## Run
1. Install Node.js 20+ and PostgreSQL.
2. Copy `.env.example` to `.env` and set DATABASE_URL/JWT_SECRET.
3. `npm install`
4. `npm --prefix backend install`
5. `npm --prefix frontend install`
6. `npm --prefix backend exec prisma generate`
7. `npm --prefix backend exec prisma migrate dev --name init`
8. `npm --prefix backend run seed`
9. `npm run dev`

Seed accounts (change immediately):
owner / ChangeMe!Owner123
command / ChangeMe!Command123
dispatch / ChangeMe!Dispatch123
