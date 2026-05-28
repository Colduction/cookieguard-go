package cookieguard

import (
	"sync/atomic"

	"github.com/colduction/cookieguard-go/internal/core"
	"github.com/gofiber/fiber/v2"
)

// New creates a new middleware handler
func New(config ...Config) fiber.Handler {
	var (
		cfg  = configDefault(config...)
		opts atomic.Pointer[core.Options]
	)
	opts.Store(&cfg.options)

	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		o := opts.Load()
		core.DecryptRequestCookies(&c.Request().Header, o)
		err := c.Next()
		core.EncryptResponseCookies(&c.Response().Header, o)
		return err
	}
}
