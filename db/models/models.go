package models

import (
	"github.com/utkarshgupta2804/csrf-project/randomstrings" // Import your custom package for generating secure random strings.
	jwt "github.com/dgrijalva/jwt-go" // Import the JWT library for creating and parsing JWT tokens.
	"time" // Import time utilities for setting token expiration durations.
)

// User represents a simple user model with username, hashed password, and role.
type User struct {
	Username, PasswordHash, Role string
}

// https://tools.ietf.org/html/rfc7519
// TokenClaims represents custom claims for JWT tokens.
// It embeds jwt.StandardClaims and adds custom fields for Role and CSRF secret.
// This struct defines the payload stored inside a JWT.
type TokenClaims struct {
	jwt.StandardClaims           // Embeds standard claims like exp, iat, sub.
	Role string `json:"role"`    // Custom claim: user's role.
	Csrf string `json:"csrf"`    // Custom claim: a unique CSRF secret.
}

// RefreshTokenValidTime defines how long a refresh token stays valid (72 hours).
const RefreshTokenValidTime = time.Hour * 72

// AuthTokenValidTime defines how long an auth token (access token) stays valid (15 minutes).
const AuthTokenValidTime = time.Minute * 15

// GenerateCSRFSecret generates a secure random CSRF secret for embedding in JWTs.
func GenerateCSRFSecret() (string, error) {
	return randomstrings.GenerateRandomString(32)
}