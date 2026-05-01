package main

import (
	"log"
	"net/http"
	"os"

	"insighta-web/handlers"

	"github.com/joho/godotenv"
)

func main() {
	godotenv.Load()

	mux := http.NewServeMux()

	// Auth routes
	mux.HandleFunc("GET /", handlers.Login)
	// mux.HandleFunc("GET /auth/github", func(w http.ResponseWriter, r *http.Request) {
	// 	http.Redirect(w, r, "http://54.91.238.144:8080/auth/github", http.StatusTemporaryRedirect)
	// })
	mux.HandleFunc("GET /auth/github", handlers.GithubLogin)
	mux.HandleFunc("GET /auth/github/callback", handlers.GithubCallback)
	mux.HandleFunc("POST /logout", handlers.Logout)

	// Protected pages
	mux.HandleFunc("GET /dashboard", handlers.Dashboard)
	mux.HandleFunc("GET /profiles", handlers.Profiles)
	mux.HandleFunc("GET /profiles/create", handlers.CreateProfilePage)
	mux.HandleFunc("POST /profiles/create", handlers.CreateProfile)
	mux.HandleFunc("GET /profiles/export", handlers.ExportProfiles)
	mux.HandleFunc("GET /profiles/{id}", handlers.ProfileDetail)
	mux.HandleFunc("POST /profiles/{id}/delete", handlers.DeleteProfile)
	mux.HandleFunc("GET /search", handlers.Search)
	mux.HandleFunc("GET /account", handlers.Account)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	log.Printf("Web portal running on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}
