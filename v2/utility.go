package cookieguard

import "github.com/colduction/cookieguard-go/internal/core"

// EncryptCookie Encrypts a cookie data with specific encryption key
func EncryptCookie(data, key []byte) ([]byte, error) {
	return core.EncryptCookie(data, key)
}

// DecryptCookie Decrypts a cookie data with specific encryption key
func DecryptCookie(data, key []byte) ([]byte, error) {
	return core.DecryptCookie(data, key)
}

// GenerateKey Generates an encryption key according to the length.
// If the length does not match the valid AES block size, it generates a 32-byte encryption key instead.
func GenerateKey(length ...int) []byte {
	return core.GenerateKey(length...)
}
