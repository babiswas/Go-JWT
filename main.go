package main

import (
	"Auth/JWT"
	"fmt"
	"log"
	"net/http"
)

func handler1(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "my home")
}

func main() {
	http.HandleFunc("/login", JWT.Login)
	http.HandleFunc("/home", JWT.Home)
	http.HandleFunc("/refresh", JWT.Refresh)
	http.HandleFunc("/hello", handler1)
	log.Fatal(http.ListenAndServe(":8081", nil))
}
