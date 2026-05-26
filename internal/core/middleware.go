package core

import (
	"bytes"

	"github.com/valyala/fasthttp"
)

type requestCookieUpdate struct {
	key   []byte
	value []byte
}

type responseCookieUpdate struct {
	cookie *fasthttp.Cookie
}

func DecryptRequestCookies(header *fasthttp.RequestHeader, opts Options) {
	var (
		oldKeys [][]byte
		updates []requestCookieUpdate
	)

	for key, value := range header.Cookies() {
		keyOwned := false
		valueOwned := false

		if opts.EncryptKeys {
			decryptedKey, err := opts.Decryptor(key, opts.Key)
			if err != nil {
				if opts.SkipUnencryptedCookies {
					oldKeys = append(oldKeys, bytes.Clone(key))
					continue
				}
				if !opts.SuppressErrors {
					panic(err)
				}
			} else {
				oldKeys = append(oldKeys, bytes.Clone(key))
				key = decryptedKey
				keyOwned = true
			}
		}

		if !isDisabledKey(key, opts.ExceptKeys) {
			if opts.EncryptValues {
				decryptedValue, err := opts.Decryptor(value, opts.Key)
				if err != nil {
					if opts.SkipUnencryptedCookies {
						if opts.EncryptKeys {
							oldKeys = append(oldKeys, retainCookieBytes(key, keyOwned))
						}
						continue
					}
					if opts.SuppressErrors {
						updates = append(updates, requestCookieUpdate{
							key:   retainCookieBytes(key, keyOwned),
							value: bytes.Clone(value),
						})
						continue
					}
					updates = append(updates, requestCookieUpdate{key: retainCookieBytes(key, keyOwned)})
					continue
				}
				value = decryptedValue
				valueOwned = true
			}
			updates = append(updates, requestCookieUpdate{
				key:   retainCookieBytes(key, keyOwned),
				value: retainCookieBytes(value, valueOwned),
			})
		}
	}

	for i := range updates {
		header.SetCookieBytesKV(updates[i].key, updates[i].value)
	}

	if opts.EncryptKeys {
		for _, key := range oldKeys {
			header.DelCookieBytes(key)
		}
	}
}

func EncryptResponseCookies(header *fasthttp.ResponseHeader, opts Options) {
	var (
		oldKeys [][]byte
		updates []responseCookieUpdate
	)

	for key, value := range header.Cookies() {
		if isDisabledKey(key, opts.ExceptKeys) {
			continue
		}

		encryptedCookie := fasthttp.AcquireCookie()
		if err := encryptedCookie.ParseBytes(value); err != nil {
			fasthttp.ReleaseCookie(encryptedCookie)
			if opts.SuppressErrors {
				continue
			}
			panic(err)
		}

		if opts.EncryptKeys {
			encryptedKey, err := opts.Encryptor(encryptedCookie.Key(), opts.Key)
			if err != nil {
				if opts.SuppressErrors {
					updates = append(updates, responseCookieUpdate{cookie: encryptedCookie})
					continue
				}
				fasthttp.ReleaseCookie(encryptedCookie)
				panic(err)
			}
			oldKeys = append(oldKeys, bytes.Clone(key))
			encryptedCookie.SetKeyBytes(encryptedKey)
		}

		if opts.EncryptValues {
			encryptedValue, err := opts.Encryptor(encryptedCookie.Value(), opts.Key)
			if err != nil {
				if opts.SuppressErrors {
					updates = append(updates, responseCookieUpdate{cookie: encryptedCookie})
					continue
				}
				fasthttp.ReleaseCookie(encryptedCookie)
				panic(err)
			}
			encryptedCookie.SetValueBytes(encryptedValue)
		}
		updates = append(updates, responseCookieUpdate{cookie: encryptedCookie})
	}

	for i := range updates {
		header.SetCookie(updates[i].cookie)
		fasthttp.ReleaseCookie(updates[i].cookie)
	}

	if opts.EncryptKeys {
		for _, key := range oldKeys {
			header.DelCookieBytes(key)
		}
	}
}

func retainCookieBytes(value []byte, owned bool) []byte {
	if owned {
		return value
	}
	return bytes.Clone(value)
}

func isDisabledKey(key []byte, except map[string]struct{}) bool {
	if len(key) == 0 || len(except) == 0 {
		return false
	}
	_, ok := except[string(key)]
	return ok
}
