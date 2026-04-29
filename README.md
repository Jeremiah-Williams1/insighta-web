# Insighta Labs+ — Web Portal

Browser-based interface for the Insighta Labs+ platform. Built with Go server-side rendering and GitHub OAuth.

---

## Pages

| Route | Description | Access |
|-------|-------------|--------|
| `/` | Login page | Public |
| `/dashboard` | Overview + quick actions | All users |
| `/profiles` | List with filters + pagination | All users |
| `/profiles/{id}` | Profile detail | All users |
| `/profiles/create` | Create profile form | Admin only |
| `/search` | Natural language search | All users |
| `/account` | Account info + permissions | All users |

---

## Authentication

The web portal uses GitHub OAuth with PKCE — the same flow as the CLI but browser-based.

**Flow:**
1. User clicks "Login with GitHub"
2. Portal redirects to GitHub OAuth page
3. User approves
4. GitHub redirects back to `/auth/github/callback`
5. Portal sends `code + code_verifier` to backend
6. Backend returns JWT + refresh token
7. Portal stores both as **HTTP-only cookies**

### HTTP-only cookies
Tokens are never accessible via JavaScript. The browser automatically sends them with every request. This protects against XSS attacks — even if malicious JavaScript runs on the page, it cannot read or steal the tokens.

### CSRF Protection
Every form includes a hidden `csrf_token` field. The portal validates this token matches a cookie value before processing any POST request. This prevents cross-site request forgery attacks.

---

## Running Locally

**Prerequisites:** Go 1.26+, running backend

```bash
git clone <repo>
cd insighta-web

# Install dependencies
go mod tidy

# Create .env
cp .env.example .env
# Fill in values

go run main.go
# Portal runs on http://localhost:3000
```

## Environment Variables

```env
API_BASE_URL=http://localhost:8080   # your backend URL
GITHUB_CLIENT_ID=                    # same as backend
REDIRECT_URI=http://localhost:3000/auth/github/callback
PORT=3000
```

**Important:** Add `http://localhost:3000/auth/github/callback` as an allowed callback URL in your GitHub OAuth App settings.

---

## Architecture

The web portal is a server-side rendered Go application. It does not talk to the database directly — it is a client of the backend API, identical in role to the CLI.

```
Browser → Web Portal (Go) → Backend API → PostgreSQL
```

Every page handler:
1. Reads the `access_token` cookie
2. Calls the backend API with that token
3. Receives JSON data
4. Renders an HTML template with the data
5. Returns HTML to the browser

This means all business logic, authentication verification, and role enforcement happens on the backend — not in the portal.

---

## Deployment

```bash
# On your server
git clone <repo>
cd insighta-web
go build -o web .

# Create .env with production values
nano .env

# Run
nohup ./web > web.log 2>&1 &
```
