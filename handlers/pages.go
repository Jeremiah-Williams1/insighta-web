package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// baseData holds fields every page needs
type baseData struct {
	CSRFToken string
	Role      string
	Username  string
	Email     string
	AvatarURL string
}

// getBaseData reads the JWT from the access_token cookie and extracts user info
// Every protected page calls this first
func getBaseData(r *http.Request) (baseData, error) {
	cookie, err := r.Cookie("access_token")
	if err != nil {
		return baseData{}, fmt.Errorf("not authenticated")
	}

	// Decode JWT claims without verifying signature
	// We trust our own backend issued it — we just need the role/username
	claims, err := decodeJWT(cookie.Value)
	if err != nil {
		return baseData{}, fmt.Errorf("invalid token")
	}

	role, _ := claims["role"].(string)
	username, _ := claims["username"].(string)
	email, _ := claims["email"].(string)

	return baseData{
		CSRFToken: getCSRFToken(r),
		Role:      role,
		Username:  username,
		Email:     email,
	}, nil
}

// decodeJWT reads the payload of a JWT without verifying it
// Safe because we only use it for display — all real auth happens on the backend
func decodeJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token")
	}
	payload, err := base64DecodeRaw(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	return claims, err
}

func base64DecodeRaw(s string) ([]byte, error) {
	// JWT uses base64url without padding — add padding back before decoding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// redirectIfNotAuth checks for the access_token cookie and redirects to login if missing
func redirectIfNotAuth(w http.ResponseWriter, r *http.Request) bool {
	_, err := r.Cookie("access_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return true
	}
	return false
}

// Dashboard renders the dashboard page with total profile count
func Dashboard(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}

	base, err := getBaseData(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Fetch total profile count from backend
	resp, err := callAPI(r, "GET", "/api/profiles?limit=1", nil)
	var total int
	if err == nil {
		defer resp.Body.Close()
		var result struct {
			Total int `json:"total"`
		}
		json.NewDecoder(resp.Body).Decode(&result)
		total = result.Total
	}

	renderTemplate(w, "dashboard.html", map[string]any{
		"CSRFToken":     base.CSRFToken,
		"Role":          base.Role,
		"Username":      base.Username,
		"Email":         base.Email,
		"AvatarURL":     base.AvatarURL,
		"TotalProfiles": total,
	})
}

// Profile is a local struct for rendering profile data in templates
type Profile struct {
	ID                 string
	Name               string
	Gender             string
	GenderProbability  float64
	Age                int
	AgeGroup           string
	CountryID          string
	CountryName        string
	CountryProbability float64
	CreatedAt          time.Time
}

// Filters holds the active filter values so templates can pre-fill form fields
type Filters struct {
	Gender    string
	AgeGroup  string
	CountryID string
	SortBy    string
}

// Profiles renders the profiles list page
func Profiles(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}

	base, err := getBaseData(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	q := r.URL.Query()
	page := q.Get("page")
	if page == "" {
		page = "1"
	}
	limit := q.Get("limit")
	if limit == "" {
		limit = "10"
	}

	// Build query string from whatever filters are active
	filters := Filters{
		Gender:    q.Get("gender"),
		AgeGroup:  q.Get("age_group"),
		CountryID: q.Get("country_id"),
		SortBy:    q.Get("sort_by"),
	}

	apiPath := fmt.Sprintf("/api/profiles?page=%s&limit=%s", page, limit)
	extraParams := ""
	if filters.Gender != "" {
		apiPath += "&gender=" + filters.Gender
		extraParams += "&gender=" + filters.Gender
	}
	if filters.AgeGroup != "" {
		apiPath += "&age_group=" + filters.AgeGroup
		extraParams += "&age_group=" + filters.AgeGroup
	}
	if filters.CountryID != "" {
		apiPath += "&country_id=" + filters.CountryID
		extraParams += "&country_id=" + filters.CountryID
	}
	if filters.SortBy != "" {
		apiPath += "&sort_by=" + filters.SortBy
		extraParams += "&sort_by=" + filters.SortBy
	}

	resp, err := callAPI(r, "GET", apiPath, nil)
	if err != nil {
		renderTemplate(w, "profiles.html", map[string]any{
			"CSRFToken": base.CSRFToken,
			"Role":      base.Role,
			"Error":     "Failed to fetch profiles",
		})
		return
	}
	defer resp.Body.Close()

	var result struct {
		Total      int              `json:"total"`
		Page       int              `json:"page"`
		Limit      int              `json:"limit"`
		TotalPages int              `json:"total_pages"`
		Data       []map[string]any `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	// Convert raw map data to typed Profile structs for the template
	profiles := make([]Profile, 0, len(result.Data))
	for _, p := range result.Data {
		profiles = append(profiles, mapToProfile(p))
	}

	renderTemplate(w, "profiles.html", map[string]any{
		"CSRFToken":   base.CSRFToken,
		"Role":        base.Role,
		"Profiles":    profiles,
		"Total":       result.Total,
		"Page":        result.Page,
		"Limit":       result.Limit,
		"TotalPages":  result.TotalPages,
		"Filters":     filters,
		"QueryString": extraParams,
	})
}

// ProfileDetail renders a single profile page
func ProfileDetail(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}

	base, err := getBaseData(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	id := r.PathValue("id")
	resp, err := callAPI(r, "GET", "/api/profiles/"+id, nil)
	if err != nil || resp.StatusCode == http.StatusNotFound {
		http.Redirect(w, r, "/profiles", http.StatusFound)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Data map[string]any `json:"data"`
	}
	json.NewDecoder(resp.Body).Decode(&result)
	profile := mapToProfile(result.Data)

	renderTemplate(w, "profile.html", map[string]any{
		"CSRFToken": base.CSRFToken,
		"Role":      base.Role,
		"Profile":   profile,
	})
}

// CreateProfilePage renders the create profile form (admin only)
func CreateProfilePage(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}
	base, err := getBaseData(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if base.Role != "admin" {
		http.Redirect(w, r, "/profiles", http.StatusFound)
		return
	}
	renderTemplate(w, "create.html", map[string]any{
		"CSRFToken": base.CSRFToken,
		"Role":      base.Role,
	})
}

// CreateProfile handles the form POST to create a profile (admin only)
func CreateProfile(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}
	if !validateCSRF(r) {
		http.Redirect(w, r, "/profiles", http.StatusFound)
		return
	}

	base, err := getBaseData(r)
	if err != nil || base.Role != "admin" {
		http.Redirect(w, r, "/profiles", http.StatusFound)
		return
	}

	name := r.FormValue("name")
	if name == "" {
		renderTemplate(w, "create.html", map[string]any{
			"CSRFToken": base.CSRFToken,
			"Role":      base.Role,
			"Error":     "Name is required",
		})
		return
	}

	payload, _ := json.Marshal(map[string]string{"name": name})
	resp, err := callAPI(r, "POST", "/api/profiles", bytes.NewReader(payload))
	if err != nil || resp.StatusCode != http.StatusCreated {
		renderTemplate(w, "create.html", map[string]any{
			"CSRFToken": base.CSRFToken,
			"Role":      base.Role,
			"Error":     "Failed to create profile",
		})
		return
	}
	defer resp.Body.Close()

	http.Redirect(w, r, "/profiles", http.StatusFound)
}

// DeleteProfile handles the POST to delete a profile (admin only)
func DeleteProfile(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}
	if !validateCSRF(r) {
		http.Redirect(w, r, "/profiles", http.StatusFound)
		return
	}

	base, err := getBaseData(r)
	if err != nil || base.Role != "admin" {
		http.Redirect(w, r, "/profiles", http.StatusFound)
		return
	}

	id := r.PathValue("id")
	callAPI(r, "DELETE", "/api/profiles/"+id, nil)
	http.Redirect(w, r, "/profiles", http.StatusFound)
}

// ExportProfiles proxies the CSV export from the backend
func ExportProfiles(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}

	resp, err := callAPI(r, "GET", "/api/profiles/export?format=csv", nil)
	if err != nil {
		http.Redirect(w, r, "/profiles", http.StatusFound)
		return
	}
	defer resp.Body.Close()

	// Copy the CSV headers and body directly to the browser
	// This triggers a file download
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="profiles_%s.csv"`, time.Now().Format("20060102_150405")))
	io.Copy(w, resp.Body)
}

// Search renders the search page
func Search(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}
	base, err := getBaseData(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := r.URL.Query().Get("q")
	data := map[string]any{
		"CSRFToken": base.CSRFToken,
		"Role":      base.Role,
		"Query":     query,
	}

	if query != "" {
		resp, err := callAPI(r, "GET", "/api/profiles/search?q="+query, nil)
		if err == nil {
			defer resp.Body.Close()
			var result struct {
				Total int              `json:"total"`
				Data  []map[string]any `json:"data"`
			}
			json.NewDecoder(resp.Body).Decode(&result)
			profiles := make([]Profile, 0, len(result.Data))
			for _, p := range result.Data {
				profiles = append(profiles, mapToProfile(p))
			}
			data["Profiles"] = profiles
			data["Total"] = result.Total
		}
	}

	renderTemplate(w, "search.html", data)
}

// Account renders the account page
func Account(w http.ResponseWriter, r *http.Request) {
	if redirectIfNotAuth(w, r) {
		return
	}
	base, err := getBaseData(r)
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderTemplate(w, "account.html", map[string]any{
		"CSRFToken": base.CSRFToken,
		"Role":      base.Role,
		"Username":  base.Username,
		"Email":     base.Email,
		"AvatarURL": base.AvatarURL,
	})
}

// mapToProfile converts a raw JSON map to a typed Profile struct
func mapToProfile(p map[string]any) Profile {
	profile := Profile{}
	if v, ok := p["id"].(string); ok {
		profile.ID = v
	}
	if v, ok := p["name"].(string); ok {
		profile.Name = v
	}
	if v, ok := p["gender"].(string); ok {
		profile.Gender = v
	}
	if v, ok := p["gender_probability"].(float64); ok {
		profile.GenderProbability = v
	}
	if v, ok := p["age"].(float64); ok {
		profile.Age = int(v)
	}
	if v, ok := p["age_group"].(string); ok {
		profile.AgeGroup = v
	}
	if v, ok := p["country_id"].(string); ok {
		profile.CountryID = v
	}
	if v, ok := p["country_name"].(string); ok {
		profile.CountryName = v
	}
	if v, ok := p["country_probability"].(float64); ok {
		profile.CountryProbability = v
	}
	if v, ok := p["created_at"].(string); ok {
		profile.CreatedAt, _ = time.Parse(time.RFC3339, v)
	}
	return profile
}
