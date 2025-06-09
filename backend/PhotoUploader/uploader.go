package photouploader

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var jwtSecret = []byte("123123123123123123123123123123123")

func extractUserIDFromJWT(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("missing Authorization header")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid Authorization header format")
	}

	tokenStr := parts[1]

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired JWT token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid JWT claims format")
	}

	hasuraClaims, ok := claims["https://hasura.io/jwt/claims"].(map[string]interface{})
	if !ok {
		return "", errors.New("missing Hasura claims")
	}

	userID, ok := hasuraClaims["x-hasura-user-id"].(string)
	if !ok {
		return "", errors.New("user ID not found in token")
	}

	return userID, nil
}

func UploadPhotoHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handlePhotoUpload(db, w, r)
		} else if r.Method == http.MethodGet {
			handlePhotoRetrieval(db, w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

type UploadRequest struct {
	ImageBase64 string `json:"image_base64"`
}

func handlePhotoUpload(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID, err := extractUserIDFromJWT(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var req UploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ImageBase64 == "" {
		http.Error(w, "Invalid request body or missing image_base64", http.StatusBadRequest)
		return
	}

	photoID := uuid.New()
	_, err = db.Exec(
		`INSERT INTO user_photos (id, user_id, image_base64, uploaded_at) VALUES ($1, $2, $3, $4)`,
		photoID, userID, req.ImageBase64, time.Now(),
	)
	if err != nil {
		http.Error(w, "Database insert failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "Uploaded successfully",
		"id":      photoID.String(),
	})
}

func handlePhotoRetrieval(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID, err := extractUserIDFromJWT(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	rows, err := db.Query(
		`SELECT id, image_base64, uploaded_at FROM user_photos WHERE user_id = $1 ORDER BY uploaded_at DESC`,
		userID,
	)
	if err != nil {
		http.Error(w, "Failed to query photos: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Photo struct {
		ID        uuid.UUID `json:"id"`
		ImageData string    `json:"image_base64"`
		Uploaded  string    `json:"uploaded_at"`
	}

	var photos []Photo
	for rows.Next() {
		var p Photo
		var uploadedAt time.Time

		if err := rows.Scan(&p.ID, &p.ImageData, &uploadedAt); err != nil {
			http.Error(w, "Failed to parse photo data", http.StatusInternalServerError)
			return
		}
		p.Uploaded = uploadedAt.Format(time.RFC3339)
		photos = append(photos, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(photos)
}
