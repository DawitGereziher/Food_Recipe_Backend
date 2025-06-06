package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
    "Auth/PhotoUploader"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("123123123123123123123123123123123")

var db *sql.DB

type HasuraClaims struct {
	jwt.RegisteredClaims
	Hasura map[string]interface{} `json:"https://hasura.io/jwt/claims"`
}

type AuthPayload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name,omitempty"`
		Role     string `json:"role,omitempty"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

func generateJWT(userID uuid.UUID, role string) (string, error) {
	claims := HasuraClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Hasura: map[string]interface{}{
			"x-hasura-user-id":       userID.String(),
			"x-hasura-default-role":  role,
			"x-hasura-allowed-roles": []string{"user", "admin", "anonymous"},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var payload AuthPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	email := payload.Email
	name := payload.Name
	password := payload.Password
	role := payload.Role
	if role == "" {
		role = "user"
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Password hashing failed", http.StatusInternalServerError)
		return
	}

	id := uuid.New()
	_, err = db.Exec(`INSERT INTO users (id, name, email, password, role) VALUES ($1, $2, $3, $4, $5)`,
		id, name, email, string(hashedPassword), role,
	)

	if err != nil {
		fmt.Println("Error:", err)
		fmt.Println("Received email:", payload.Email)
		http.Error(w, "Email already exists or DB error", http.StatusBadRequest)
		return
	}

	token, err := generateJWT(id, role)

	if err != nil {
		http.Error(w, "JWT creation failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(AuthResponse{Token: token})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var payload AuthPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid JSON"})
		return
	}

	email := payload.Email
	password := payload.Password

	var role string
	var id uuid.UUID
	var hashedPassword string

	err := db.QueryRow(`SELECT id, password, role FROM users WHERE email = $1`, email).
		Scan(&id, &hashedPassword, &role)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "User not found"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"message": "Invalid password"})
		return
	}

	token, err := generateJWT(id, role)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"message": "JWT creation failed"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AuthResponse{Token: token})
}

func main() {
	var err error
	db, err = sql.Open("postgres", "postgres://dave:14141414@postgres:5432/mydb?sslmode=disable")
	if err != nil {
		log.Fatal("Failed to connect to DB:", err)
	}

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/upload-photo", photouploader.UploadPhotoHandler(db))

	fmt.Println("🚀 Server running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
