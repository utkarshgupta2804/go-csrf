package db

import (
	"errors"
	"github.com/utkarshgupta2804/csrf-project/db/models"  // Custom user model definitions
	"github.com/utkarshgupta2804/csrf-project/randomstrings"  // Utility for generating random strings
	"golang.org/x/crypto/bcrypt"  // Password hashing library
	"log"
)

// users is an in-memory map storing user data with UUID as the key
var users = map[string]models.User{}

// refreshTokens is an in-memory map storing refresh token statuses
// The key is the JTI (JSON Token Identifier) and value could represent status
var refreshTokens map[string]string

// InitDB initializes the database by creating the refreshTokens map
// This is called at application startup
func InitDB() {
	refreshTokens = make(map[string]string)
}

// StoreUser creates a new user in the in-memory database
// Parameters:
//   - username: the user's login name
//   - password: plaintext password (will be hashed)
//   - role: user role/privilege level
// Returns:
//   - uuid: unique identifier for the user
//   - error: if any step fails
func StoreUser(username string, password string, role string) (uuid string, err error) {
	// Generate a random UUID for the user
	uuid, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	// Ensure UUID is unique by checking for collisions
	u := models.User{}
	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	// Generate bcrypt hash of the password for secure storage
	passwordHash, hashErr := generateBcryptHash(password)
	if hashErr != nil {
		err = hashErr
		return
	}

	// Store the user in the map
	users[uuid] = models.User{username, passwordHash, role}

	return uuid, err
}

// DeleteUser removes a user from the database by UUID
func DeleteUser(uuid string) {
	delete(users, uuid)
}

// FetchUserById retrieves a user by their UUID
// Returns:
//   - User object if found
//   - Error if user doesn't exist
func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	// Compare with blank user to check existence
	if blankUser != u {
		return u, nil
	} else {
		return u, errors.New("User not found that matches given uuid")
	}
}

// FetchUserByUsername searches for a user by username
// Returns:
//   - User object if found
//   - User's UUID if found
//   - Error if user doesn't exist
func FetchUserByUsername(username string) (models.User, string, error) {
	// Linear search through all users (inefficient for large datasets)
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}

	return models.User{}, "", errors.New("User not found that matches given username")
}

// StoreRefreshToken generates and stores a new refresh token identifier
// Returns:
//   - jti: the unique token identifier
//   - error: if generation fails
func StoreRefreshToken() (jti string, err error) {
	// Generate random JTI
	jti, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return jti, err
	}

	// Ensure JTI is unique
	for refreshTokens[jti] != "" {
		jti, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return jti, err
		}
	}

	// Mark token as valid in storage
	refreshTokens[jti] = "valid"

	return jti, err
}

// DeleteRefreshToken removes a refresh token from storage
func DeleteRefreshToken(jti string) {
	delete(refreshTokens, jti)
}

// CheckRefreshToken verifies if a refresh token exists and is valid
func CheckRefreshToken(jti string) bool {
	return refreshTokens[jti] != ""
}

// LogUserIn authenticates a user by username and password
// Returns:
//   - User object if authentication succeeds
//   - User's UUID if authentication succeeds
//   - Error if authentication fails
func LogUserIn(username string, password string) (models.User, string, error) {
	// First fetch the user by username
	user, uuid, userErr := FetchUserByUsername(username)
	log.Println(user, uuid, userErr)
	if userErr != nil {
		return models.User{}, "", userErr
	}

	// Verify the provided password against the stored hash
	return user, uuid, checkPasswordAgainstHash(user.PasswordHash, password)
}

// generateBcryptHash creates a secure hash of a password using bcrypt
func generateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

// checkPasswordAgainstHash compares a plaintext password with a bcrypt hash
func checkPasswordAgainstHash(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}