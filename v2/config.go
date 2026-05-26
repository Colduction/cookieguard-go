package cookieguard

import (
	"github.com/colduction/cookieguard-go/internal/core"
	"github.com/gofiber/fiber/v2"
)

// Config defines the config for middleware.
type Config struct {
	// Array of cookie keys that should not be encrypted.
	//
	// Optional. Default: nil
	Except []string

	// Unique key to encode & decode cookies.
	//
	// Required. Key length should be 16, 24, or 32 characters.
	// You may use `encryptcookie.GenerateKey()` to generate a new key.
	Key []byte

	// Next defines a function to skip this middleware when returned true.
	//
	// Optional. Default: nil
	Next func(c *fiber.Ctx) bool

	// Custom function to encrypt cookies.
	//
	// Optional. Default: EncryptCookie
	Encryptor func(message, key []byte) ([]byte, error)

	// Custom function to decrypt cookies.
	//
	// Optional. Default: DecryptCookie
	Decryptor func(ciphertext, key []byte) ([]byte, error)

	// Encrypt cookie keys.
	//
	// Optional. Default: false
	EncryptKeys bool

	// Encrypt cookie values.
	//
	// Optional. Default: true
	EncryptValues bool

	// Suppress errors instead of panic on errors.
	//
	// Optional. Default: false
	SuppressErrors bool

	// Skip received cookies which are not encrypted.
	//
	// Optional. Default: false
	SkipUnencryptedCookies bool

	options core.Options
}

// ConfigDefault is the default config
var ConfigDefault = Config{
	Next:                   nil,
	Except:                 nil,
	Key:                    nil,
	Encryptor:              EncryptCookie,
	Decryptor:              DecryptCookie,
	EncryptKeys:            false,
	EncryptValues:          true,
	SuppressErrors:         false,
	SkipUnencryptedCookies: false,
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	// Set default config
	var (
		cfg                 = ConfigDefault
		useDefaultEncryptor = true
		useDefaultDecryptor = true
	)

	// Override config if provided
	if len(config) > 0 {
		cfg = config[0]
		useDefaultEncryptor = cfg.Encryptor == nil
		useDefaultDecryptor = cfg.Decryptor == nil

		// Set default values

		if cfg.Next == nil {
			cfg.Next = ConfigDefault.Next
		}

		if cfg.Encryptor == nil {
			cfg.Encryptor = ConfigDefault.Encryptor
		}

		if cfg.Decryptor == nil {
			cfg.Decryptor = ConfigDefault.Decryptor
		}

		if !cfg.EncryptKeys && !cfg.EncryptValues {
			cfg.EncryptValues = ConfigDefault.EncryptValues
		}
	}

	if len(cfg.Key) == 0 {
		panic("fiber: cookie guard middleware requires key")
	}

	options, err := core.NewOptions(
		cfg.Key,
		cfg.Except,
		cfg.Encryptor,
		cfg.Decryptor,
		cfg.EncryptKeys,
		cfg.EncryptValues,
		cfg.SuppressErrors,
		cfg.SkipUnencryptedCookies,
		useDefaultEncryptor,
		useDefaultDecryptor,
	)
	if err != nil {
		panic(err)
	}
	cfg.Encryptor = options.Encryptor
	cfg.Decryptor = options.Decryptor
	cfg.options = options

	return cfg
}
