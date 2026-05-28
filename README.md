# cookieguard-go

[![Go Reference](https://pkg.go.dev/badge/github.com/colduction/cookieguard-go.svg)](https://pkg.go.dev/github.com/colduction/cookieguard-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/colduction/cookieguard-go)](https://goreportcard.com/report/github.com/colduction/cookieguard-go)
![GitHub License](https://img.shields.io/github/license/Colduction/cookieguard-go)

A Fiber middleware that transparently encrypts outgoing cookies and decrypts incoming ones using AES-GCM. Your handlers always read and write plain values — encryption happens automatically.

## Installation

Pick the module that matches your Fiber version:

```sh
go get -u github.com/colduction/cookieguard-go/v2
# or
go get -u github.com/colduction/cookieguard-go/v3
```

## Quick Start

```go
// Load from env in production; generate randomly for local dev
key := []byte(os.Getenv("COOKIEGUARD_KEY"))
if len(key) == 0 {
    key = cookieguard.GenerateKey()
}

app.Use(cookieguard.New(cookieguard.Config{
    Key: key,
}))
```

> **Production note:** Use the same key on every restart. If the key changes, existing encrypted cookies can't be decrypted.

## Example (Fiber v2)

```go
package main

import (
    "log"
    "os"

    "github.com/colduction/cookieguard-go/v2"
    "github.com/gofiber/fiber/v2"
)

func main() {
    key := []byte(os.Getenv("COOKIEGUARD_KEY"))
    if len(key) == 0 {
        key = cookieguard.GenerateKey()
    }

    app := fiber.New()
    app.Use(cookieguard.New(cookieguard.Config{
        Key:    key,
        Except: []string{"csrf_token"},
    }))

    app.Get("/login", func(c *fiber.Ctx) error {
        c.Cookie(&fiber.Cookie{Name: "session", Value: "user-123", HTTPOnly: true, Secure: true})
        return c.SendString("logged in")
    })

    app.Get("/me", func(c *fiber.Ctx) error {
        return c.SendString("session: " + c.Cookies("session")) // already decrypted
    })

    log.Fatal(app.Listen(":3000"))
}
```

For Fiber v3, import `cookieguard-go/v3` and change `*fiber.Ctx` to `fiber.Ctx`.

## Configuration

| Field                     | Type       | Default      | Description                                                        |
| ------------------------- | ---------- | ------------ | ------------------------------------------------------------------ |
| `Key`                     | `[]byte`   | **required** | AES key — must be 16, 24, or 32 bytes.                             |
| `Except`                  | `[]string` | `nil`        | Cookie names to skip (not encrypted or decrypted).                 |
| `Next`                    | func       | `nil`        | Skip the middleware when this returns `true`.                      |
| `Encryptor` / `Decryptor` | func       | built-in     | Override with custom encrypt/decrypt functions.                    |
| `EncryptKeys`             | `bool`     | `false`      | Also encrypt cookie names.                                         |
| `EncryptValues`           | `bool`     | `true`       | Encrypt cookie values.                                             |
| `SuppressErrors`          | `bool`     | `false`      | Silently ignore encryption/decryption errors instead of panicking. |
| `SkipUnencryptedCookies`  | `bool`     | `false`      | Pass unencrypted cookies through as-is (useful during migration).  |

## Migration from Plaintext Cookies

Enable these flags during rollout so old plaintext cookies still work:

```go
app.Use(cookieguard.New(cookieguard.Config{
    Key:                    key,
    SkipUnencryptedCookies: true,
    SuppressErrors:         true,
}))
```

Remove them once all clients have received encrypted cookies.

## License

This project is released under the MIT License. See [LICENSE](LICENSE).
