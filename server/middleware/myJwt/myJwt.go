package myJwt

import (
	"crypto/rsa"                                                    // RSA cryptographic operations
	"errors"                                                        // Error creation and handling
	"github.com/utkarshgupta2804/csrf-project/db"                   // Database operations
	"github.com/utkarshgupta2804/csrf-project/db/models"            // Data models and structures
	jwt "github.com/dgrijalva/jwt-go"                               // JWT library for token operations
	"io/ioutil"                                                     // File I/O operations
	"log"                                                           // Logging functionality
	"time"                                                          // Time operations
)

// Constants defining the file paths for RSA key pairs
const (
	privKeyPath = "keys/app.rsa"      // Path to private key file (used for signing tokens)
	pubKeyPath  = "keys/app.rsa.pub"  // Path to public key file (used for verifying tokens)
)

// Global variables to store the RSA key pair
var (
	verifyKey *rsa.PublicKey   // Public key for verifying JWT signatures
	signKey   *rsa.PrivateKey  // Private key for signing JWTs
)

// InitJWT initializes the JWT system by loading RSA keys from files
func InitJWT() error {
	// Read the private key file from disk
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		// Return error if file cannot be read
		return err
	}

	// Parse the PEM-encoded private key bytes into an RSA private key
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		// Return error if private key parsing fails
		return err
	}

	// Read the public key file from disk
	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		// Return error if file cannot be read
		return err
	}

	// Parse the PEM-encoded public key bytes into an RSA public key
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		// Return error if public key parsing fails
		return err
	}

	// Return nil if all operations succeeded
	return nil
}

// CreateNewTokens generates a new pair of auth and refresh tokens with CSRF protection
// Returns: authToken (short-lived), refreshToken (long-lived), csrfSecret, error
func CreateNewTokens(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {

	// Generate a random CSRF secret for this token pair
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		// Return early if CSRF secret generation fails
		return
	}

	// Create the refresh token (long-lived token for getting new auth tokens)
	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)

	// Create the auth token (short-lived token for API access)
	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		// Return early if auth token creation fails
		return
	}

	// Return all generated tokens and secrets
	return
}

// CheckAndRefreshTokens validates existing tokens and refreshes them if needed
// This is the core function that handles token validation and renewal
func CheckAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {

	// First check: Ensure CSRF token is present
	if oldCsrfSecret == "" {
		log.Println("No CSRF token!")
		err = errors.New("Unauthorized")
		return
	}

	// Parse and validate the auth token structure
	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Return the public key for signature verification
		return verifyKey, nil
	})
	
	// Extract claims from the parsed auth token
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		// Return error if claims cannot be extracted
		return
	}
	
	// Verify CSRF token matches the one stored in the JWT
	if oldCsrfSecret != authTokenClaims.Csrf {
		log.Println("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
		return
	}

	// Check if the auth token is still valid (not expired)
	if authToken.Valid {
		log.Println("Auth token is valid")

		// Token is valid, just extend the refresh token expiry
		newCsrfSecret = authTokenClaims.Csrf  // Keep the same CSRF secret
		
		// Update refresh token expiration time
		newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
		newAuthTokenString = oldAuthTokenString  // Keep the same auth token
		return
		
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		// Auth token is invalid, check the specific reason
		log.Println("Auth token is not valid")
		
		// Check if the token is expired (vs other validation errors)
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			log.Println("Auth token is expired")

			// Token is expired but might be refreshable
			// Create a new auth token using the refresh token
			newAuthTokenString, newCsrfSecret, err = updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)
			if err != nil {
				return
			}

			// Update refresh token expiration
			newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
			if err != nil {
				return
			}

			// Update refresh token with new CSRF secret
			newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
			return
		} else {
			// Token has validation errors other than expiration
			log.Println("Error in auth token")
			err = errors.New("Error in auth token")
			return
		}
	} else {
		// Unknown error occurred during token parsing
		log.Println("Error in auth token")
		err = errors.New("Error in auth token")
		return
	}

	// Should not reach here, but return unauthorized as fallback
	err = errors.New("Unauthorized")
	return
}

// createAuthTokenString creates a new short-lived authentication token
func createAuthTokenString(uuid string, role string, csrfSecret string) (authTokenString string, err error) {
	// Set expiration time for auth token (short duration for security)
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	
	// Create token claims with user info and expiration
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject:   uuid,         // User's unique identifier
			ExpiresAt: authTokenExp, // When this token expires
		},
		role,       // User's role (admin, user, etc.)
		csrfSecret, // CSRF protection token
	}

	// Create JWT with RS256 signing algorithm and the claims
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)

	// Sign the token with the private key to create the final token string
	authTokenString, err = authJwt.SignedString(signKey)
	return
}

// createRefreshTokenString creates a new long-lived refresh token
func createRefreshTokenString(uuid string, role string, csrfString string) (refreshTokenString string, err error) {
	// Set expiration time for refresh token (longer duration)
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	
	// Store refresh token in database and get a unique JTI (JWT ID)
	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}

	// Create refresh token claims
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        refreshJti,        // Unique token ID for database tracking
			Subject:   uuid,              // User's unique identifier
			ExpiresAt: refreshTokenExp,   // When this token expires
		},
		role,       // User's role
		csrfString, // CSRF protection token
	}

	// Create and sign the refresh token
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

// updateRefreshTokenExp extends the expiration time of an existing refresh token
func updateRefreshTokenExp(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	// Parse the existing refresh token
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	// Extract claims from the old token
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	// Create new expiration time
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	// Create new claims with updated expiration but same other data
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,      // Keep same JTI
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject, // Keep same user
			ExpiresAt: refreshTokenExp,                              // New expiration
		},
		oldRefreshTokenClaims.Role, // Keep same role
		oldRefreshTokenClaims.Csrf, // Keep same CSRF token
	}

	// Create and sign the new refresh token
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

// updateAuthTokenString creates a new auth token using a valid refresh token
func updateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	// Parse the refresh token to validate it
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	
	// Extract claims from refresh token
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = errors.New("Error reading jwt claims")
		return
	}

	// Check if refresh token exists in database (not revoked)
	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {

		// Verify refresh token is still valid (not expired)
		if refreshToken.Valid {

			// Parse the old auth token to get user info
			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})

			// Extract claims from old auth token
			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = errors.New("Error reading jwt claims")
				return
			}

			// Generate new CSRF secret for security
			csrfSecret, err = models.GenerateCSRFSecret()
			if err != nil {
				return
			}

			// Create new auth token with same user info but new CSRF secret
			newAuthTokenString, err = createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)

			return
		} else {
			// Refresh token has expired
			log.Println("Refresh token has expired!")

			// Remove expired refresh token from database
			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

			err = errors.New("Unauthorized")
			return
		}
	} else {
		// Refresh token has been revoked (removed from database)
		log.Println("Refresh token has been revoked!")

		err = errors.New("Unauthorized")
		return
	}
}

// RevokeRefreshToken invalidates a refresh token by removing it from the database
func RevokeRefreshToken(refreshTokenString string) error {
	// Parse the refresh token to get its ID
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return errors.New("Could not parse refresh token with claims")
	}

	// Extract claims to get the token ID
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("Could not read refresh token claims")
	}

	// Remove the refresh token from the database
	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

	return nil
}

// updateRefreshTokenCsrf updates the CSRF secret in an existing refresh token
func updateRefreshTokenCsrf(oldRefreshTokenString string, newCsrfString string) (newRefreshTokenString string, err error) {
	// Parse the old refresh token
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	// Extract claims from old token
	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	// Create new claims with updated CSRF secret
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,        // Keep same JTI
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,   // Keep same user
			ExpiresAt: oldRefreshTokenClaims.StandardClaims.ExpiresAt, // Keep same expiration
		},
		oldRefreshTokenClaims.Role, // Keep same role
		newCsrfString,              // Update CSRF secret
	}

	// Create and sign new refresh token
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

// GrabUUID extracts the user UUID from an auth token without validating the signature
// Note: This function intentionally doesn't validate the token signature
func GrabUUID(authTokenString string) (string, error) {
	// Parse token without signature validation (notice the error returned in the key function)
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "", errors.New("Error fetching claims")
	})
	
	// Extract claims from the token
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("Error fetching claims")
	}

	// Return the user UUID from the Subject field
	return authTokenClaims.StandardClaims.Subject, nil
}