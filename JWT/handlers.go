package JWT

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

var jwt_key = []byte("secret_key")
var users = map[string]string{"user1": "pass1", "user2": "pass2"}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	epassword, ok := users[credentials.Username]
	if !ok || epassword != credentials.Password {
		w.WriteHeader(http.StatusUnauthorized)
	}
	expiration_time := time.Now().Add(time.Minute + 5)
	claims := &Claims{Username: credentials.Username, StandardClaims: jwt.StandardClaims{ExpiresAt: expiration_time.Unix()}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token_string, err := token.SignedString(jwt_key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   token_string,
		Expires: expiration_time,
	})
	fmt.Println("POST Operation Completed")
}

func Home(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	fmt.Println(cookie)
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token_string := cookie.Value
	fmt.Println(token_string)
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(token_string, claims, func(t *jwt.Token) (interface{}, error) {
		return jwt_key, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	fmt.Fprintf(w, "HomePage")
	fmt.Println("GET operation completed")
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	token_string := cookie.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(token_string, claims, func(t *jwt.Token) (interface{}, error) {
		return jwt_key, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}
	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	expiration_time := time.Now().Add(time.Minute + 5)
	claims.ExpiresAt = expiration_time.Unix()
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token_string, err = token.SignedString(jwt_key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "refresh_token",
		Value:   token_string,
		Expires: expiration_time,
	})
	fmt.Println("operation completed")

}
