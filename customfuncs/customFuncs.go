package customfuncs

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/google/uuid"

	"github.com/jf-tech/omniparser/transformctx"
)

// CustomFuncType is the type of custom function. Has to use interface{} given we support
// non-variadic and variadic functions.
type CustomFuncType = interface{}

// CustomFuncs is a map from custom func names to an actual custom func.
type CustomFuncs = map[string]CustomFuncType

// Merge merges multiple custom func maps into one.
func Merge(funcs ...CustomFuncs) CustomFuncs {
	merged := make(CustomFuncs)
	for _, fs := range funcs {
		for name, f := range fs {
			merged[name] = f
		}
	}
	return merged
}

func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// CommonCustomFuncs contains the most basic and frequently-used custom functions that are suitable
// for all versions of schemas.
var CommonCustomFuncs = map[string]CustomFuncType{
	// keep these custom funcs lexically sorted
	"coalesce":                Coalesce,
	"concat":                  Concat,
	"dateTimeLayoutToRFC3339": DateTimeLayoutToRFC3339,
	"dateTimeToEpoch":         DateTimeToEpoch,
	"dateTimeToRFC3339":       DateTimeToRFC3339,
	"epochToDateTimeRFC3339":  EpochToDateTimeRFC3339,
	"lower":                   Lower,
	"now":                     Now,
	"upper":                   Upper,
	"uuidv3":                  UUIDv3,
	"uuidv4":                  UUIDv4,
	"encryptAesEcb":           EncryptAESECB,
	"encryptAesGcm":           EncryptAESGCM,
}

// Coalesce returns the first non-empty string of the input strings. If no input strings are given or
// all of them are empty, then an empty string is returned. Note: a blank string (with only whitespaces)
// is not considered as empty.
func Coalesce(_ *transformctx.Ctx, strs ...string) (string, error) {
	for _, str := range strs {
		if str != "" {
			return str, nil
		}
	}
	return "", nil
}

// Concat concatenates a number of strings together. If no strings specified, "" is returned.
func Concat(_ *transformctx.Ctx, strs ...string) (string, error) {
	var w strings.Builder
	for _, s := range strs {
		w.WriteString(s)
	}
	return w.String(), nil
}

// Lower lowers the case of an input string.
func Lower(_ *transformctx.Ctx, s string) (string, error) {
	return strings.ToLower(s), nil
}

// Upper uppers the case of an input string.
func Upper(_ *transformctx.Ctx, s string) (string, error) {
	return strings.ToUpper(s), nil
}

// UUIDv3 uses MD5 to produce a consistent/stable UUID for an input string.
func UUIDv3(_ *transformctx.Ctx, s string) (string, error) {
	return uuid.NewMD5(uuid.Nil, []byte(s)).String(), nil
}

// Generates an UUID.
func UUIDv4(_ *transformctx.Ctx) (string, error) {
	return uuid.New().String(), nil
}

// Apply AES ECB encryption for an input string
func EncryptAESECB(_ *transformctx.Ctx, key string, s string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	plaintext := PKCS7Padding([]byte(s), blockSize)

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += blockSize {
		block.Encrypt(ciphertext[i:i+blockSize], plaintext[i:i+blockSize])
	}
	encodedCiphertext := hex.EncodeToString(ciphertext)

	return encodedCiphertext, nil
}

// Apply AES GCM encryption for an input string
func EncryptAESGCM(_ *transformctx.Ctx, key string, s string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(s), nil)
	encodedCiphertext := hex.EncodeToString(ciphertext)

	return encodedCiphertext, nil
}
