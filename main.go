package main

// https://www.elephantsql.com/docs/go.html

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

type Error struct {
	Message string `json:"message"`
}

const (
	host     = "localhost"
	port     = 5432
	pguser   = "postgres"
	password = "Pass@word1"
	dbname   = "user-account"
)

var db *sql.DB

func main() {
	// pguser was colliding with the user struct!!
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, pguser, password, dbname)
	dbtemp, err := sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}

	// Make db global
	db = dbtemp
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/signup", signUp).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")

	// If you get through the TokenVerifyMiddleWare function, you go the function passed in - protectedEndpoint..
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router))
}

func signUp(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error

	json.NewDecoder(r.Body).Decode(&user)

	fmt.Println(user)
	spew.Dump(user)

	if user.Email == "" {
		// respond with error - bad request
		error.Message = "Email missing."
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	if user.Password == "" {
		// respond with error - bad request
		error.Message = "Password missing"
		respondWithError(w, http.StatusBadRequest, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}

	user.Password = string(hash)
	fmt.Println("pass text:", user.Password)
	fmt.Println("Email text:", user.Email)
	fmt.Println(db)
	fmt.Println("*********")

	sqlStatement :=
		`INSERT INTO users (email, password)
		VALUES ($1, $2)
		RETURNING id;`
	err = db.QueryRow(sqlStatement, user.Email, user.Password).Scan(&user.ID)

	if err != nil {
		error.Message = "Server error."
		respondWithError(w, http.StatusInternalServerError, error)
		return
	}

	fmt.Println("New record ID is:", user.ID)

	user.Password = ""
	w.Header().Set("Content-Type", "application/json")
	responseJSON(w, user)

}

func responseJSON(w http.ResponseWriter, data interface{}) {

	json.NewEncoder(w).Encode(data)
}

func respondWithError(w http.ResponseWriter, status int, error Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(error)
	return
}

//***** Everything needed to login *******
// https://tools.ietf.org/html/rfc7519

func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"

	// TODO: What is the HS256 type of encryption??
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{"email": user.Email, "iss": "course"})

	//spew.Dump(token)

	tokenString, err := token.SignedString([]byte(secret))

	//fmt.Println("tokenString:", tokenString)

	if err != nil {
		fmt.Println("**** Error in Generate Token ****")
		log.Fatal(err)
	}

	return tokenString, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	var jwt JWT
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

	// Get the pre-hashed password from user json struct and store it temp
	preHashedPassword := user.Password

	row := db.QueryRow("select * from users where email=$1", user.Email)

	// Jam the db field into the user struct
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	spew.Dump(user)

	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			respondWithError(w, http.StatusBadRequest, error)
			return
		} else {
			fmt.Println("***** Error in Login DB Query ****")
			log.Fatal(err)
		}
	}

	hashedPassword := user.Password

	// Takes a hashed password and compairs it to a non-hased source
	// Convert the string values to []byte 'slices'
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(preHashedPassword))

	if err != nil {
		error.Message = "Invalid Password"
		respondWithError(w, http.StatusUnauthorized, error)
		return
	}

	token, err := GenerateToken(user)

	if err != nil {
		fmt.Println("**** Error in Login Token Generate ****")
		log.Fatal(err)
	}

	w.WriteHeader(http.StatusOK)
	jwt.Token = token

	responseJSON(w, jwt)
}

//******* Protected endpoint **************

// Func with caps can be exported, which we dont want
func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("successfully called protectedEndpoint"))
	fmt.Println("protectedEndPoint invoked.")
}

// This is the gatekeeper to the protected End Point
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	fmt.Println("TokenVerifyMiddleWare invoked.")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				// Unvalidated token and no signature
				spew.Dump(token)

				// This function will validate the bearerToken and return signature value ***
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error in the bearerToken")
				}
				return []byte("foo"), nil
				//return []byte("secret"), nil
			})

			if error != nil {
				fmt.Println("****** Unmatched secret *******")
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
			// dumps valid token with signature
			spew.Dump(token)

			// bool on the valid claim
			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				respondWithError(w, http.StatusUnauthorized, errorObject)
				return
			}
		} else {
			// If the bearer token not two parts ***
			errorObject.Message = "Invalid token."
			respondWithError(w, http.StatusUnauthorized, errorObject)
			return
		}
	})
}
