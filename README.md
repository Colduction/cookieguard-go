# cookieguard-go

[![Go Reference](https://pkg.go.dev/badge/github.com/colduction/cookieguard-go.svg)](https://pkg.go.dev/github.com/colduction/cookieguard-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/colduction/cookieguard-go)](https://goreportcard.com/report/github.com/colduction/cookieguard-go)
![GitHub License](https://img.shields.io/github/license/Colduction/cookieguard-go)

`cookieguard-go` is a Fiber middleware that encrypts cookies before they leave your app and decrypts them before your handlers read them.

It is useful when you want cookie values, and optionally cookie names, to be unreadable and tamper-resistant on the client side.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Fiber v2 Example](#fiber-v2-example)
- [Fiber v3 Example](#fiber-v3-example)
- [Configuration](#configuration)
- [How It Works](#how-it-works)
- [Key Management](#key-management)
- [Migration Tips](#migration-tips)
- [Custom Encryption](#custom-encryption)
- [Testing](#testing)
- [FAQ](#faq)
- [License](#license)

## Features

- Supports both `github.com/gofiber/fiber/v2` and `github.com/gofiber/fiber/v3`.
- Encrypts response cookies automatically.
- Decrypts request cookies automatically.
- Uses authenticated AES-GCM encryption through `github.com/colduction/aes-go`.
- Supports 16, 24, and 32 byte AES keys.
- Can skip selected cookie names with `Except`.
- Can encrypt cookie names with `EncryptKeys`.
- Can help migrations with `SkipUnencryptedCookies`.
- Uses shared internal code for the v2 and v3 implementations.

## Installation

Install the package that matches your Fiber version:

```sh
go get -u github.com/colduction/cookieguard-go/v2
```

or:

```sh
go get -u github.com/colduction/cookieguard-go/v3
```

## Quick Start

The smallest setup needs only a key:

```go
key := cookieguard.GenerateKey()

app.Use(cookieguard.New(cookieguard.Config{
	Key: key,
}))
```

Important: `GenerateKey()` creates a new random key. That is great for tests and local experiments, but in production you should load the same secret key on every restart. If the key changes, old encrypted cookies cannot be decrypted.

## Fiber v2 Example

```go
package main

import (
	"log"
	"os"

	cookieguard "github.com/colduction/cookieguard-go/v2"
	"github.com/gofiber/fiber/v2"
)

func main() {
	key := []byte(os.Getenv("COOKIEGUARD_KEY"))
	if len(key) == 0 {
		key = cookieguard.GenerateKey()
	}

	app := fiber.New()

	app.Use(cookieguard.New(cookieguard.Config{
		Key: key,
		Except: []string{
			"csrf_token",
		},
	}))

	app.Get("/login", func(c *fiber.Ctx) error {
		c.Cookie(&fiber.Cookie{
			Name:     "session",
			Value:    "user-123",
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Lax",
		})

		return c.SendString("session cookie was encrypted")
	})

	app.Get("/me", func(c *fiber.Ctx) error {
		session := c.Cookies("session")
		return c.SendString("decrypted session: " + session)
	})

	log.Fatal(app.Listen(":3000"))
}
```

## Fiber v3 Example

```go
package main

import (
	"log"
	"os"

	cookieguard "github.com/colduction/cookieguard-go/v3"
	"github.com/gofiber/fiber/v3"
)

func main() {
	key := []byte(os.Getenv("COOKIEGUARD_KEY"))
	if len(key) == 0 {
		key = cookieguard.GenerateKey()
	}

	app := fiber.New()

	app.Use(cookieguard.New(cookieguard.Config{
		Key: key,
		Except: []string{
			"csrf_token",
		},
	}))

	app.Get("/login", func(c fiber.Ctx) error {
		c.Cookie(&fiber.Cookie{
			Name:     "session",
			Value:    "user-123",
			HTTPOnly: true,
			Secure:   true,
			SameSite: "Lax",
		})

		return c.SendString("session cookie was encrypted")
	})

	app.Get("/me", func(c fiber.Ctx) error {
		session := c.Cookies("session")
		return c.SendString("decrypted session: " + session)
	})

	log.Fatal(app.Listen(":3000"))
}
```

## Configuration

```go
app.Use(cookieguard.New(cookieguard.Config{
	Key:                    key,
	Except:                 []string{"csrf_token"},
	EncryptKeys:            false,
	EncryptValues:          true,
	SuppressErrors:         false,
	SkipUnencryptedCookies: false,
}))
```

| Field                    | Type                                   | Default         | What it does                                                                                  |
| ------------------------ | -------------------------------------- | --------------- | --------------------------------------------------------------------------------------------- |
| `Key`                    | `[]byte`                               | required        | AES key used to encrypt and decrypt cookies. Must be 16, 24, or 32 bytes.                     |
| `Except`                 | `[]string`                             | `nil`           | Cookie names that should not be encrypted or decrypted.                                       |
| `Next`                   | Fiber handler predicate                | `nil`           | Skips the middleware when it returns `true`.                                                  |
| `Encryptor`              | `func([]byte, []byte) ([]byte, error)` | `EncryptCookie` | Custom cookie encryption function.                                                            |
| `Decryptor`              | `func([]byte, []byte) ([]byte, error)` | `DecryptCookie` | Custom cookie decryption function.                                                            |
| `EncryptKeys`            | `bool`                                 | `false`         | Encrypts cookie names as well as values.                                                      |
| `EncryptValues`          | `bool`                                 | `true`          | Encrypts cookie values.                                                                       |
| `SuppressErrors`         | `bool`                                 | `false`         | Keeps going instead of panicking on encryption/decryption errors.                             |
| `SkipUnencryptedCookies` | `bool`                                 | `false`         | Leaves unencrypted request cookies untouched when decryption fails. Useful during migrations. |

## How It Works

On the request path:

1. The browser sends cookies to your app.
2. `cookieguard-go` decrypts encrypted cookies.
3. Your Fiber handlers read normal plaintext values with `c.Cookies(...)`.

On the response path:

1. Your Fiber handlers set normal cookies with `c.Cookie(...)`.
2. `cookieguard-go` encrypts those cookies before the response is sent.
3. The browser stores the encrypted cookie value.

By default, only cookie values are encrypted. Cookie names stay readable. Set `EncryptKeys: true` if you also want names encrypted.

## Key Management

Use a 16, 24, or 32 byte key:

```go
key := cookieguard.GenerateKey(32)
```

For production, store the key somewhere stable, such as an environment variable, secret manager, or deployment secret.

Example:

```go
key := []byte(os.Getenv("COOKIEGUARD_KEY"))
if len(key) != 16 && len(key) != 24 && len(key) != 32 {
	log.Fatal("COOKIEGUARD_KEY must be 16, 24, or 32 bytes")
}
```

Do not generate a new key on every production startup unless you intentionally want to invalidate all existing cookies.

## Migration Tips

If your app already has plaintext cookies and you enable `cookieguard-go`, those old cookies cannot be decrypted.

For a softer rollout, use:

```go
app.Use(cookieguard.New(cookieguard.Config{
	Key:                    key,
	SkipUnencryptedCookies: true,
	SuppressErrors:         true,
}))
```

This lets old plaintext cookies pass through while new response cookies are written encrypted.

After users have rotated into encrypted cookies, you can disable those options again.

## Custom Encryption

Most apps should use the defaults. If you need a custom format, provide matching encryptor and decryptor functions:

```go
app.Use(cookieguard.New(cookieguard.Config{
	Key: key,
	Encryptor: func(message, key []byte) ([]byte, error) {
		return cookieguard.EncryptCookie(message, key)
	},
	Decryptor: func(ciphertext, key []byte) ([]byte, error) {
		return cookieguard.DecryptCookie(ciphertext, key)
	},
}))
```

Both functions must agree on the same encoding format. If the decryptor cannot read what the encryptor writes, requests will fail or cookies will be skipped depending on your error settings.

## Testing

Run the full test suite:

```sh
go test ./...
```

Run the core cookie codec benchmark:

```sh
go test ./internal/core -bench=BenchmarkCookieCodec -benchmem -run=^$
```

## FAQ

### Should I encrypt cookie keys?

Usually no. Encrypting values is enough for most apps. Encrypting keys can make debugging harder and may complicate interoperability with other middleware.

Use `EncryptKeys: true` only when hiding cookie names is important for your app.

### Can I exclude a cookie from encryption?

Yes:

```go
Except: []string{"csrf_token", "public_preference"}
```

Cookies in `Except` are left as-is.

### Why did all users get logged out after a deploy?

The encryption key probably changed. Encrypted cookies can only be decrypted with the same key that encrypted them.

### Is this a replacement for `Secure`, `HTTPOnly`, and `SameSite`?

No. Encryption protects the cookie contents. You should still set normal cookie security flags:

```go
c.Cookie(&fiber.Cookie{
	Name:     "session",
	Value:    "user-123",
	HTTPOnly: true,
	Secure:   true,
	SameSite: "Lax",
})
```

### What happens if a cookie is tampered with?

The default AES-GCM decryptor rejects tampered cookies. Depending on your config, the middleware will panic, suppress the error, or skip unencrypted cookies.

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
