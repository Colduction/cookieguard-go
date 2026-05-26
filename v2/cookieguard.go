package cookieguard

import (
	"github.com/colduction/cookieguard-go/internal/core"
	"github.com/gofiber/fiber/v2"
)

// New creates a new middleware handler
func New(config ...Config) fiber.Handler {
	// Set default config
	cfg := configDefault(config...)
	options := cfg.options

	// Return new handler
	return func(c *fiber.Ctx) error {
		// Skip middleware if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		core.DecryptRequestCookies(&c.Request().Header, options)

		// Continue stack
		err := c.Next()

		core.EncryptResponseCookies(&c.Response().Header, options)

		return err
	}
}
