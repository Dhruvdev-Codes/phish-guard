# Implementation Guide: User & Developer RBAC for Phish-Guard

A comprehensive, step-by-step engineering roadmap to implement role-based access control (RBAC), user authentication, and an isolated developer admin portal for the **Phish-Guard** cybersecurity platform without exposing application secrets or compromising zero-telemetry client-side privacy.

---

## 🏗️ Architecture Overview

```
                        +----------------------------+
                        |     Public Landing Page    |
                        |      (Phish-Guard UI)      |
                        +--------------+-------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
         [ Standard Users ]                      [ Privileged Devs ]
                   |                                       |
          +--------v--------+                     +--------v--------+
          |  /login /signup |                     |   /dev/login    |
          |  (Email/Pass/   |                     | (MFA + Obf. URL |
          |   OAuth / Magic)|                     |  + Dev RLS Key) |
          +--------+--------+                     +--------+--------+
                   |                                       |
          +--------v--------+                     +--------v--------+
          | Protected User  |                     | Developer Admin |
          |    Dashboard    |                     |  Control Engine |
          | (Scan & History)|                     | (Heuristics/C2) |
          +-----------------+                     +-----------------+
```

---

## Phase 1: Authentication Engine & Identity Setup

1. **Select an Identity Provider:**
   - **Recommended Choice:** Supabase Auth (GoTrue + PostgreSQL) or Firebase Auth for zero-server maintenance, built-in email/password authentication, JWT signing, and native Row-Level Security (RLS).
   - **Alternative Self-Hosted:** PocketBase, Appwrite, or custom Express/Fastify server with Argon2id + JWT + HttpOnly Cookies.

2. **Configure Authentication Policies:**
   - Enable Email/Password registration with mandatory email verification.
   - Enforce strong password complexity rules (minimum 12 characters, uppercase, lowercase, numbers, special symbols).
   - Enable rate-limiting on `/login`, `/register`, and `/dev/login` endpoints (e.g., maximum 5 failed attempts per 15 minutes per IP) to mitigate brute-force and credential-stuffing attacks.


---

## Phase 2: Database Schema & Role Design

1. **User Profiles Table (`public.profiles`):**
   - Directly references the auth provider's unique user identifier (`auth.users.id`).
   - Fields: `id` (UUID, Primary Key), `email` (Text, Unique), `full_name` (Text), `role` (Text, default `'user'`), `created_at` (Timestamp), `updated_at` (Timestamp).

2. **Define the Role Hierarchy:**
   - `user`: Standard access to AI heuristics scanner, email header inspector, QR quishing sandbox, typosquat radar, HTML smuggling detector, and personal threat logs.
   - `developer`: Privileged access to global phishing blacklist rules, heuristic threshold tuning, C2 threat intelligence feeds, system telemetry, and user management.
   - **Constraint:** Hardcode a database check constraint `CHECK (role IN ('user', 'developer'))` and default all public registrations strictly to `'user'`.

3. **Database-Level Authorization (Row-Level Security - RLS):**
   - **Rule 1 (User Profile Isolation):** Users can read and update only their own profile row (`auth.uid() = id`).
   - **Rule 2 (Scan Log Privacy):** Users can query and delete only scans tied to their `user_id`.
   - **Rule 3 (Rule Engine Protection):** Only authenticated accounts verified with `role = 'developer'` have `INSERT`, `UPDATE`, or `DELETE` permissions on detection rules and blacklists. Regular users have read-only access to published rules.

4. **Bootstrapping Developer Identities:**
   - Developer accounts cannot be created via the public sign-up form.
   - Register your administrative account through the normal registration flow, then execute a direct database query or management console update to promote your account:
     ```sql
     UPDATE public.profiles SET role = 'developer' WHERE email = 'developer@phish-guard.io';
     ```

---

## Phase 3: Route Architecture & UI Separation

| Route | Target Audience | Access Requirement | Description |
| :--- | :--- | :--- | :--- |
| `/login` | Regular Users | Public | User sign-in with email/password or magic links. |
| `/register` | Regular Users | Public | Public account creation (auto-assigned `user` role). |
| `/dashboard` | Regular Users | Authenticated (`user` / `developer`) | Interactive scanning workbench, personal threat metrics, and saved scan reports. |
| `/dev/login` | Developers Only | Public (Hidden/Protected) | Dedicated terminal-style login portal for engineering access. |
| `/dev/admin` | Developers Only | Authenticated (`developer` only) | Core Control Engine: manage regex rules, custom heuristics, domain blacklist, and SOC telemetry. |

---

## Phase 4: Access Control & Middleware Enforcement

1. **Client-Side Route Guards:**
   - Create a reactive auth listener (or Next.js middleware) that intercepts navigation events.
   - If an unauthenticated user attempts to visit `/dashboard` or `/dev/admin`, immediately redirect to `/login` or `/dev/login`.
   - If an authenticated `user` attempts to navigate to `/dev/admin`, abort the route, log an unauthorized access attempt, and redirect to `/dashboard`.

2. **Server-Side API Verification:**
   - Every API route (or Edge function) must extract and verify the JWT bearer token from the incoming request header.
   - Verify the `role` claim in the decoded payload or query the database profile before executing privileged operations.
   - Return standard `HTTP 401 Unauthorized` for missing/expired tokens, and `HTTP 403 Forbidden` for role mismatches.

---

## Phase 5: Testing & Security Validation

1. **Role Boundary & Privilege Escalation Testing:**
   - Attempt to modify database records or access `/dev/admin` endpoints while logged in as a standard `user`. Ensure the API returns `403 Forbidden`.
   - Verify that manipulating client-side state variables in browser dev tools does not grant access to developer API routes.

2. **Developer Privileges Verification:**
   - Log into `/dev/login` with developer credentials.
   - Add a test malicious domain or custom regex heuristic rule, and verify it updates the global detection pipeline in real-time.

3. **Session Revocation & Hardening:**
   - Confirm that clicking "Logout" invalidates both the client-side session state and the backend refresh token cookie.
   - Ensure that password resets immediately terminate all existing active sessions across all devices.

3. **Establish Secure Session Handling:**
   - Use short-lived JSON Web Tokens (JWT) for access (15–30 minutes expiration) paired with secure Refresh Tokens stored in `HttpOnly`, `SameSite=Strict`, `Secure` cookies.
   - Never store raw access tokens or admin API keys in `localStorage` or `sessionStorage` where they are vulnerable to Cross-Site Scripting (XSS).
