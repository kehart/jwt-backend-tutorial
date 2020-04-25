package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	//"github.com/davecgh/go-spew/spew"

)

/*
Models
 */
type User struct {
	ID 			int `json:"id"`
	Email		string `json:"email"`
	Password	string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

// Global DB variable
var db *sql.DB

// URL for DB connection declared
// postgres://ksggpgzb:bV1fFTMvXIMUVBH-AW3Tx0MvQP0jR9Du@drona.db.elephantsql.com:5432/ksggpgzb
func main() {

	pgUrl, err := pq.ParseURL("postgres://ksggpgzb:bV1fFTMvXIMUVBH-AW3Tx0MvQP0jR9Du@drona.db.elephantsql.com:5432/ksggpgzb"); if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgUrl); if err != nil {
		log.Fatal(err)
	}

	err = db.Ping(); if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleware(protectedEndpoint)).Methods("GET")

	log.Println("Listening on port 8000")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
}

func responseJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	json.NewDecoder(r.Body).Decode(&user)

	//spew.Dump(user)
	if user.Email == "" {
		error.Message = "Email is missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.Password == "" {
		error.Message = "Password is missing"
		respondWithError(w, http.StatusBadRequest, error)
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
		respondWithError(w, http.StatusInternalServerError, error)
		return
	}
	user.Password = ""
	responseJSON(w, user)
}

func GenerateToken(user User) (string, error) {
	//var error error
	secret := "secret" // could be anything

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss": "course",
	})

	tokenString, err := token.SignedString([]byte(secret)); if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil

	// jwt = header.payload.secret
}

func login(w http.ResponseWriter, r *http.Request) {

	var user User
	json.NewDecoder(r.Body).Decode(&user)

	token, err := GenerateToken(user); if err != nil {
		log.Fatal(err)
	}
	fmt.Println(token, err)
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked")
}

func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("middleware invoked")
	return next
}


