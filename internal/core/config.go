package core

type Options struct {
	Key                    []byte
	Encryptor              Cryptor
	Decryptor              Cryptor
	ExceptKeys             map[string]struct{}
	EncryptKeys            bool
	EncryptValues          bool
	SuppressErrors         bool
	SkipUnencryptedCookies bool
}

func NewOptions(
	key []byte,
	except []string,
	encryptor Cryptor,
	decryptor Cryptor,
	encryptKeys bool,
	encryptValues bool,
	suppressErrors bool,
	skipUnencryptedCookies bool,
	useDefaultEncryptor bool,
	useDefaultDecryptor bool,
) (Options, error) {
	opts := Options{
		Key:                    key,
		Encryptor:              encryptor,
		Decryptor:              decryptor,
		ExceptKeys:             BuildExceptKeys(except),
		EncryptKeys:            encryptKeys,
		EncryptValues:          encryptValues,
		SuppressErrors:         suppressErrors,
		SkipUnencryptedCookies: skipUnencryptedCookies,
	}

	if useDefaultEncryptor || useDefaultDecryptor {
		codec, err := NewCookieCodec(key)
		if err != nil {
			return Options{}, err
		}
		if useDefaultEncryptor {
			opts.Encryptor = codec.Encrypt
		}
		if useDefaultDecryptor {
			opts.Decryptor = codec.Decrypt
		}
	}

	return opts, nil
}

func BuildExceptKeys(except []string) map[string]struct{} {
	if len(except) == 0 {
		return nil
	}

	exceptKeys := make(map[string]struct{}, len(except))
	for _, key := range except {
		exceptKeys[key] = struct{}{}
	}
	return exceptKeys
}
