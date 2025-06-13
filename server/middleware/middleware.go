package middleware

import (
	"github.com/justinas/alice"  // Alice package for chaining HTTP middleware
	"log"                        // Standard logging package
	"net/http"                   // HTTP server functionality
	"time"                       // Time operations for cookie expiration
	"strings"                    // String manipulation functions
	"github.com/utkarshgupta2804/csrf-project/server/middleware/myJwt"  // Custom JWT handling
	"github.com/utkarshgupta2804/csrf-project/server/templates"         // Template rendering
	"github.com/utkarshgupta2804/csrf-project/db"                       // Database operations
)

// NewHandler creates and returns the main HTTP handler with middleware chain
// It chains recoverHandler -> authHandler -> logicHandler using Alice
func NewHandler() http.Handler {
	// Alice.New() creates a middleware chain that will execute in order:
	// 1. recoverHandler (panic recovery)
	// 2. authHandler (authentication/authorization)
	// 3. logicHandler (main application logic)
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

// recoverHandler is a middleware that catches panics and prevents server crashes
func recoverHandler(next http.Handler) http.Handler {
	// Define the actual handler function
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			// recover() catches any panic that occurred in the handler chain
			if err := recover(); err != nil {
				// Log the panic details for debugging
				log.Panic("Recovered! Panic: %+v", err)
				// Return HTTP 500 Internal Server Error to the client
				http.Error(w, http.StatusText(500), 500)
			}
		}()

		// Call the next handler in the chain
		next.ServeHTTP(w, r)
	}

	// Convert the function to http.HandlerFunc type and return
	return http.HandlerFunc(fn)
}

// authHandler is middleware that handles authentication for protected routes
func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// Check if the current path requires authentication
		// These paths are protected and require valid JWT tokens
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser":
			log.Println("In auth restricted section")

			// Try to read the AuthToken cookie from the request
			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				// No auth cookie found - user is not authenticated
				log.Println("Unauthorized attempt! No auth cookie")
				nullifyTokenCookies(&w, r)  // Clear any existing cookies
				http.Error(w, http.StatusText(401), 401)  // Return 401 Unauthorized
				return
			} else if authErr != nil {
				// Some other error occurred while reading the cookie
				log.Panic("panic: %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)  // Return 500 Internal Server Error
				return
			}

			// Try to read the RefreshToken cookie from the request
			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				// No refresh cookie found
				log.Println("Unauthorized attempt! No refresh cookie")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)  // Redirect to login page
				return
			} else if refreshErr != nil {
				// Some other error occurred while reading the refresh cookie
				log.Panic("panic: %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			// Extract CSRF token from the request (either form data or header)
			requestCsrfToken := grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			// Validate and potentially refresh the JWT tokens
			// This function checks if tokens are valid and not expired
			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					// Tokens are invalid or expired
					log.Println("Unauthorized attempt! JWT's not valid!")
					http.Error(w, http.StatusText(401), 401)
					return
				} else {
					// Some other error occurred during token validation
					log.Println("err not nil")
					log.Panic("panic: %+v", err)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}
			log.Println("Successfully recreated jwts")

			// SECURITY WARNING: This allows requests from any origin
			// In production, this should be restricted to specific trusted domains
			w.Header().Set("Access-Control-Allow-Origin", "*")

			// If we reach here, authentication was successful
			// Set the new/refreshed tokens as cookies
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			// Set the CSRF token in the response header
			w.Header().Set("X-CSRF-Token", csrfSecret)
			
		default:
			// Path doesn't require authentication, proceed normally
		}

		// Continue to the next handler in the chain
		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// logicHandler contains the main application logic for different routes
// NOTE: This should ideally be separated into individual route handlers
func logicHandler(w http.ResponseWriter, r *http.Request) {
	// Route handling based on the request path
	switch r.URL.Path {
	case "/restricted":
		// Handle requests to the restricted area
		csrfSecret := grabCsrfFromReq(r)  // Get CSRF token from request
		// Render the restricted page template with CSRF token and greeting
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{ csrfSecret, "Hello Akhil!" })

	case "/login":
		// Handle login page requests
		switch r.Method {
		case "GET":
			// Display the login form
			// false = no error, empty string = no error message
			templates.RenderTemplate(w, "login", &templates.LoginPage{ false, "" })

		case "POST":
			// Process login form submission
			r.ParseForm()  // Parse form data from request body
			log.Println(r.Form)  // Log form data for debugging

			// Attempt to authenticate user with provided credentials
			// strings.Join() converts form array to single string
			user, uuid, loginErr := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""))
			log.Println(user, uuid, loginErr)
			
			if loginErr != nil {
				// Login failed - invalid credentials
				w.WriteHeader(http.StatusUnauthorized)  // Return 401 status
			} else {
				// Login successful - create JWT tokens for the user
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, user.Role)
				if err != nil {
					// Error creating tokens
					http.Error(w, http.StatusText(500), 500)
				}

				// Set the JWT tokens as HTTP-only cookies
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				// Send CSRF token in response header
				w.Header().Set("X-CSRF-Token", csrfSecret)

				w.WriteHeader(http.StatusOK)  // Return 200 success status
			}

		default:
			// Unsupported HTTP method for /login
			w.WriteHeader(http.StatusMethodNotAllowed)  // Return 405 status
		}
		
	case "/register":
		// Handle user registration
		switch r.Method {
		case "GET":
			// Display registration form
			templates.RenderTemplate(w, "register", &templates.RegisterPage{ false, "" })
		
		case "POST":
			// Process registration form submission
			r.ParseForm()
			log.Println(r.Form)

			// Check if username is already taken
			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			if err == nil {
				// Username already exists (no error means user was found)
				w.WriteHeader(http.StatusUnauthorized)  // Return 401 status
			} else {
				// Username is available, create new user
				role := "user"  // Default role for new users
				uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
				if err != nil {
					// Error creating user in database
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("uuid: " + uuid)

				// Create JWT tokens for the newly registered user
				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}

				// Set authentication cookies
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)

				w.WriteHeader(http.StatusOK)
			}

		default:
			// Unsupported HTTP method for /register
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		
	case "/logout":
		// Handle user logout
		// Clear authentication cookies to log user out
		nullifyTokenCookies(&w, r)
		// Redirect to login page using 302 status to force GET request
		http.Redirect(w, r, "/login", 302)

	case "/deleteUser":
		// Handle user account deletion
		log.Println("Deleting user")

		// Get the auth token to identify which user to delete
		AuthCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie {
			// No auth cookie present
			log.Println("Unauthorized attempt! No auth cookie")
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "/login", 302)
			return
		} else if authErr != nil {
			// Error reading auth cookie
			log.Panic("panic: %+v", authErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		// Extract user UUID from the JWT token
		uuid, uuidErr := myJwt.GrabUUID(AuthCookie.Value)
		if uuidErr != nil {
			// Error extracting UUID from token
			log.Panic("panic: %+v", uuidErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return
		}

		// Delete the user from the database
		db.DeleteUser(uuid)
		// Clear authentication cookies
		nullifyTokenCookies(&w, r)
		// Redirect to registration page
		http.Redirect(w, r, "/register", 302)

	default:
		// Handle all other routes with a simple OK response
		w.WriteHeader(http.StatusOK)
	}
}

// nullifyTokenCookies clears authentication cookies by setting them to expire in the past
func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	// Create auth cookie with empty value and past expiration date
	authCookie := http.Cookie{
		Name: "AuthToken",
		Value: "",
		Expires: time.Now().Add(-1000 * time.Hour),  // Set to expire 1000 hours ago
		HttpOnly: true,  // Prevent JavaScript access for security
	}
	// Set the cookie in the response
	http.SetCookie(*w, &authCookie)

	// Create refresh cookie with empty value and past expiration date
	refreshCookie := http.Cookie{
		Name: "RefreshToken",
		Value: "",
		Expires: time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	// If a refresh token exists, revoke it from the database
	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		// No refresh cookie present, nothing to revoke
		return
	} else if refreshErr != nil {
		// Error reading refresh cookie
		log.Panic("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	}

	// Revoke the refresh token in the database to prevent future use
	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

// setAuthAndRefreshCookies sets new JWT tokens as HTTP-only cookies
func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
	// Create auth token cookie
	authCookie := http.Cookie{
		Name: "AuthToken",
		Value: authTokenString,
		HttpOnly: true,  // Prevent JavaScript access for security
	}
	http.SetCookie(*w, &authCookie)

	// Create refresh token cookie
	refreshCookie := http.Cookie{
		Name: "RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
}

// grabCsrfFromReq extracts CSRF token from either form data or request headers
func grabCsrfFromReq(r *http.Request) string {
	// First try to get CSRF token from form data
	csrfFromFrom := r.FormValue("X-CSRF-Token")

	if csrfFromFrom != "" {
		// Found in form data, return it
		return csrfFromFrom
	} else {
		// Not in form data, try request headers
		return r.Header.Get("X-CSRF-Token")
	}
}