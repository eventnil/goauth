package domain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

func Aes256Encode(
	plaintext string,
	key []byte,
	iv []byte,
) (encodedString string, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	size := block.BlockSize()
	bPlaintext := pkcs5Padding([]byte(plaintext), size)

	ciphertext := make([]byte, len(bPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, bPlaintext)
	res := hex.EncodeToString(ciphertext)
	return res, nil
}

func Aes256Decode(
	cipherText string,
	key []byte,
	iv []byte,
) (decryptedString string, error error) {
	cipherTextDecoded, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherTextDecoded, cipherTextDecoded)
	cipherTextDecoded, err = pkcs5UnPadding(cipherTextDecoded)
	if err != nil {
		return "", err
	}

	return string(cipherTextDecoded), nil
}

func pkcs5Padding(
	ciphertext []byte,
	blockSize int,
) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs5UnPadding(
	src []byte,
) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	j := length - unpadding
	if j >= 0 && j <= len(src) {
		return src[:(length - unpadding)], nil
	} else {
		return nil, errors.New("DECRYPTION_ERROR")
	}
}
