package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jwt-backend-tutorial/driver"
	"github.com/jwt-backend-tutorial/models"
	"github.com/jwt-backend-tutorial/utils"
	"github.com/subosito/gotenv"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"strings"
)
var db *sql.DB

func init() {
	gotenv.Load()
}

func main() {

	db = driver.ConnectDB()
	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleware(protectedEndpoint)).Methods("GET")

	log.Println("Listening on port 8000")
	log.Fatal(http.ListenAndServe(":8000", router))
}


func signup(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var error models.Error
	json.NewDecoder(r.Body).Decode(&user)

	//spew.Dump(user)
	if user.Email == "" {
		error.Message = "Email is missing"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.Password == "" {
		error.Message = "Password is missing"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}

	// Encrypt the password
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10); if err != nil {
		log.Fatal(err)
	}
	user.Password = string(hash)

	// Insert into DB
	stmt := "insert into users (email, password) values($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID); if err != nil {// since query returns id
		error.Message = "Server error"
		utils.RespondWithError(w, http.StatusInternalServerError, error)
		return
	}
	user.Password = ""
	utils.ResponseJSON(w, user)
}

func GenerateToken(user models.User) (string, error) {
	secret := os.Getenv("SECRET") // could be anything

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss": "course",
	})

	tokenString, err := token.SignedString([]byte(secret)); if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var user models.User
	var jwt models.JWT
	var error models.Error

	json.NewDecoder(r.Body).Decode(&user)

	// Validation
	if user.Email == "" {
		error.Message = "Email is missing"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.Password == "" {
		error.Message = "Password is missing"
		utils.RespondWithError(w, http.StatusBadRequest, error)
		return
	}

	password := user.Password

	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password); if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			utils.RespondWithError(w, http.StatusBadRequest, error)
			return
		} else {
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); if err != nil {
		error.Message = "Invalid Password"
		utils.RespondWithError(w, http.StatusUnauthorized, error)
		return
	}

	token, err := GenerateToken(user); if err != nil {
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	utils.ResponseJSON(w, jwt)
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked")
}

func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject models.Error
		authHeader := r.Header.Get("Authorization") // returns "KEY VAL"
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				//spew.Dump(token)

				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { // verifies the algorithm is ok
					return nil, fmt.Errorf("there was an error")
				}

				return []byte(os.Getenv("SECRET")), nil
			}); if error != nil {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid token"
			utils.RespondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})
}


