package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"os"
	"time"
)

// renderTemplate loads an HTML file from the templates folder and fills in the data
func renderTemplate(w http.ResponseWriter, tmpl string, data any) {
	// ParseFiles reads the HTML file from disk
	// FuncMap adds custom functions the templates can use (add, sub, mul)
	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"sub": func(a, b int) int { return a - b },
		"mul": func(a, b float64) float64 { return a * b },
	}
	t, err := template.New(tmpl).Funcs(funcMap).ParseFiles("templates/" + tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

// generateRandomString creates a secure random string for state and PKCE
func generateRandomString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeChallenge hashes the verifier using SHA256 for PKCE
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// setCookie is a helper to set a cookie on the response
func setCookie(w http.ResponseWriter, name, value string, httpOnly bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: httpOnly, // HttpOnly=true means JavaScript cannot read this cookie
		Path:     "/",
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearCookie deletes a cookie by setting MaxAge to -1
func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:   name,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
}

// getCSRFToken reads the CSRF token from the cookie
func getCSRFToken(r *http.Request) string {
	cookie, err := r.Cookie("csrf_token")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// validateCSRF checks that the form's csrf_token matches the cookie
func validateCSRF(r *http.Request) bool {
	cookieToken := getCSRFToken(r)
	formToken := r.FormValue("csrf_token")
	return cookieToken != "" && cookieToken == formToken
}

// Login renders the login page
func Login(w http.ResponseWriter, r *http.Request) {
	// If already logged in, redirect to dashboard
	_, err := r.Cookie("access_token")
	if err == nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	renderTemplate(w, "login.html", map[string]any{
		"Error": r.URL.Query().Get("error"),
	})
}

// GithubLogin generates PKCE params and redirects to GitHub OAuth
func GithubLogin(w http.ResponseWriter, r *http.Request) {
	state := generateRandomString()
	codeVerifier := generateRandomString()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Store state and verifier in cookies so we can validate in the callback
	// These are NOT HttpOnly because they're short-lived and only used for validation
	setCookie(w, "oauth_state", state, false, 300)
	setCookie(w, "code_verifier", codeVerifier, false, 300)

	// Generate a CSRF token and store it in a cookie for form protection
	csrfToken := generateRandomString()
	setCookie(w, "csrf_token", csrfToken, false, 86400)

	params := url.Values{}
	params.Set("client_id", os.Getenv("CLIENT_ID"))
	params.Set("redirect_uri", os.Getenv("REDIRECT_URI"))
	params.Set("scope", "user:email")
	params.Set("state", state)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")

	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+params.Encode(), http.StatusTemporaryRedirect)
}

// GithubCallback handles the redirect back from GitHub
func GithubCallback(w http.ResponseWriter, r *http.Request) {
	// 1. Validate state to prevent CSRF on the OAuth flow itself
	returnedState := r.URL.Query().Get("state")
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != returnedState {
		http.Redirect(w, r, "/?error=invalid_state", http.StatusFound)
		return
	}

	// 2. Get the code verifier from cookie
	verifierCookie, err := r.Cookie("code_verifier")
	if err != nil {
		http.Redirect(w, r, "/?error=missing_verifier", http.StatusFound)
		return
	}

	// 3. Send code + verifier to your backend's CLI callback endpoint
	// Your backend exchanges this with GitHub and returns JWT tokens
	code := r.URL.Query().Get("code")
	payload, _ := json.Marshal(map[string]string{
		"code":          code,
		"code_verifier": verifierCookie.Value,
	})

	apiBase := os.Getenv("API_BASE_URL")
	if apiBase == "" {
		apiBase = "http://localhost:8080"
	}

	resp, err := httpClient.Post(
		apiBase+"/auth/github/callback",
		"application/json",
		bytes.NewReader(payload),
	)
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Redirect(w, r, "/?error=auth_failed", http.StatusFound)
		return
	}
	defer resp.Body.Close()

	// 4. Decode the tokens from your backend
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tokens)

	if tokens.AccessToken == "" {
		http.Redirect(w, r, "/?error=no_token", http.StatusFound)
		return
	}

	// 5. Store tokens as HTTP-only cookies
	// HttpOnly=true means JavaScript in the browser CANNOT read these
	// This protects against XSS attacks stealing your tokens
	setCookie(w, "access_token", tokens.AccessToken, true, int(3*time.Minute/time.Second))
	setCookie(w, "refresh_token", tokens.RefreshToken, true, int(5*time.Minute/time.Second))

	// 6. Clean up the OAuth cookies
	clearCookie(w, "oauth_state")
	clearCookie(w, "code_verifier")

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// Logout clears all cookies and redirects to login
func Logout(w http.ResponseWriter, r *http.Request) {
	if !validateCSRF(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Tell your backend to invalidate the refresh token
	refreshCookie, err := r.Cookie("refresh_token")
	if err == nil {
		payload, _ := json.Marshal(map[string]string{
			"refresh_token": refreshCookie.Value,
		})
		apiBase := os.Getenv("API_BASE_URL")
		if apiBase == "" {
			apiBase = "http://localhost:8080"
		}
		httpClient.Post(apiBase+"/auth/logout", "application/json", bytes.NewReader(payload))
	}

	// Clear all cookies
	clearCookie(w, "access_token")
	clearCookie(w, "refresh_token")
	clearCookie(w, "csrf_token")

	http.Redirect(w, r, "/", http.StatusFound)
}
