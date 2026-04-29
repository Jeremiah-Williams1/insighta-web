package handlers

import (
	"io"
	"net/http"
	"os"
	"time"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func apiURL(path string) string {
	base := os.Getenv("API_BASE_URL")
	if base == "" {
		base = "http://localhost:8080"
	}
	return base + path
}

// callAPI makes an authenticated request to the backend using the access_token cookie
func callAPI(r *http.Request, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, apiURL(path), body)
	if err != nil {
		return nil, err
	}

	cookie, err := r.Cookie("access_token")
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+cookie.Value)
	}
	req.Header.Set("X-API-Version", "1")
	req.Header.Set("Content-Type", "application/json")

	return httpClient.Do(req)
}
