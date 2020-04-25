package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func main() {

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
	return nil
}


