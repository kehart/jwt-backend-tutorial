package utils

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/jwt-backend-tutorial/models"
	"log"
	"net/http"
	"os"
)

func RespondWithError(w http.ResponseWriter, status int, error models.Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func ResponseJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func GenerateToken(user models.User) (string, error) {
	secret := os.Getenv("SECRET")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss": "course",
	})

	tokenString, err := token.SignedString([]byte(secret)); if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}