package main

import (
	"database/sql"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"log"
	"net/http"
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

func signup(w http.ResponseWriter, r *http.Request) {
	fmt.Println("signup invoked")
}

func login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("login invoked")
}

func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protectedEndpoint invoked")
}

func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("middleware invoked")
	return next
}


