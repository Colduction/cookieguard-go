package core

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	aes "github.com/colduction/aes-go"
)

const nonceSize int = 12

var (
	errInvalidEncryptedData = errors.New("encrypted data is not valid")
	zeroNonce               [nonceSize]byte
)

type Cryptor func(message, key []byte) ([]byte, error)

type CookieCodec struct {
	aead aes.AEADCipher
}

func NewCookieCodec(key []byte) (*CookieCodec, error) {
	aead, err := aes.NewGCM(key, zeroNonce[:], nil)
	if err != nil {
		return nil, err
	}
	return &CookieCodec{aead: aead}, nil
}

func (c *CookieCodec) Encrypt(data, _ []byte) ([]byte, error) {
	return encryptCookie(c.aead, data)
}

func (c *CookieCodec) Decrypt(data, _ []byte) ([]byte, error) {
	return decryptCookie(c.aead, data)
}

func EncryptCookie(data, key []byte) ([]byte, error) {
	codec, err := NewCookieCodec(key)
	if err != nil {
		return nil, err
	}
	return encryptCookie(codec.aead, data)
}

func encryptCookie(aead aes.AEADCipher, data []byte) ([]byte, error) {
	rawLen := nonceSize + len(data) + aead.Overhead()
	raw := make([]byte, nonceSize, rawLen)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, err
	}

	raw = aead.Seal(raw, raw[:nonceSize], data, nil)
	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(encoded, raw)
	return encoded, nil
}

func DecryptCookie(data, key []byte) ([]byte, error) {
	codec, err := NewCookieCodec(key)
	if err != nil {
		return nil, err
	}
	return decryptCookie(codec.aead, data)
}

func decryptCookie(aead aes.AEADCipher, data []byte) ([]byte, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	n, err := base64.RawURLEncoding.Decode(decoded, data)
	if err != nil {
		return nil, err
	}
	decoded = decoded[:n]
	if len(decoded) < nonceSize {
		return nil, errInvalidEncryptedData
	}
	decrypted, err := aead.Open(decoded[nonceSize:nonceSize], decoded[:nonceSize], decoded[nonceSize:], nil)
	if err != nil {
		return nil, err
	}
	return decrypted, nil
}

func GenerateKey(length ...int) []byte {
	keySize := aes.KeySize256
	if len(length) != 0 {
		switch length[0] {
		case aes.KeySize128, aes.KeySize192, aes.KeySize256:
			keySize = length[0]
		}
	}
	key, _ := aes.GenerateKey(keySize)
	return key
}
