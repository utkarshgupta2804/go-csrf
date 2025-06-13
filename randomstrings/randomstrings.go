package randomstrings

import (
	"crypto/rand"          // Secure random number generator.
	"encoding/base64"      // For encoding bytes into a base64 string.
)

// GenerateRandomBytes generates 'n' secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	// Create a byte slice of length n.
	b := make([]byte, n)

	// Fill the slice with random bytes.
	_, err := rand.Read(b)

	// If an error occurred, return nil and the error.
	if err != nil {
		return nil, err
	}

	// Return the random bytes and nil error.
	return b, nil
}

// GenerateRandomString generates a secure random string of length ~ s bytes (base64 encoded).
func GenerateRandomString(s int) (string, error) {
	// Generate secure random bytes of length 's'.
	b, err := GenerateRandomBytes(s)

	// Encode the bytes into a URL-safe base64 string and return it with the error.
	return base64.URLEncoding.EncodeToString(b), err
}

