package photouploader

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"encoding/base64"

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

// UploadPhotoHandler handles photo uploads
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

func handlePhotoUpload(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID, err := extractUserIDFromJWT(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	err = r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("photo")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	uploadDir := "/app/uploads"
	if err := os.MkdirAll(uploadDir, os.ModePerm); err != nil {
		http.Error(w, "Failed to create upload directory", http.StatusInternalServerError)
		return
	}

	filePath := uploadDir + "/" + handler.Filename
	dst, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	photoID := uuid.New()
	_, err = db.Exec(`INSERT INTO user_photos (id, user_id, image_path) VALUES ($1, $2, $3)`, photoID, userID, filePath)
	if err != nil {
		http.Error(w, "Database insert failed", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message":    "Uploaded successfully",
		"photo_path": filePath,
	})
}

func handlePhotoRetrieval(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	userID, err := extractUserIDFromJWT(r)
	if err != nil {
		http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	rows, err := db.Query(`SELECT id, image_path, uploaded_at FROM user_photos WHERE user_id = $1 ORDER BY uploaded_at DESC`, userID)
	if err != nil {
		http.Error(w, "Failed to query photos", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Photo struct {
		ID        uuid.UUID `json:"id"`
		ImageData string    `json:"image_data"` // base64-encoded
		Uploaded  string    `json:"uploaded_at"`
	}

	var photos []Photo
	for rows.Next() {
		var id uuid.UUID
		var path string
		var uploaded string

		if err := rows.Scan(&id, &path, &uploaded); err != nil {
			http.Error(w, "Failed to parse photo data", http.StatusInternalServerError)
			return
		}

		fileBytes, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "Failed to read photo file: "+err.Error(), http.StatusInternalServerError)
			return
		}

		encoded := base64.StdEncoding.EncodeToString(fileBytes)
		photos = append(photos, Photo{
			ID:        id,
			ImageData: encoded,
			Uploaded:  uploaded,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(photos)
}
