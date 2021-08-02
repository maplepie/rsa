package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const (
	DEFAULT_KEY_BITS   = 1024 // default key bits.
	ADVANTAGE_KEY_BITS = 2048 // advantage key bits
)

type KeyManager struct {
	writer Writer
	reader Reader
	Key
}

func New() *KeyManager {
	return &KeyManager{}
}

func (m *KeyManager) SetWriter(writer Writer) {
	m.writer = writer
}

func (m *KeyManager) SetReader(reader Reader) {
	m.reader = reader
}

func (m *KeyManager) Save(privateFile string, publicFile string) error {
	if m.writer == nil {
		return errors.New("writer is nil")
	}
	return m.writer.Save(&m.Key, privateFile, publicFile)
}

func (m *KeyManager) Load(privateFile string, publicFile string) error {
	if m.reader == nil {
		return errors.New("reader is nil")
	}
	return m.reader.Load(&m.Key, privateFile, publicFile)
}

// 生成私钥公钥
// 明文长度(bytes)小于等于密钥长度(bytes) - 11(bytes)
// rsa的生成长度是用比特计算
func (m *KeyManager) GenerateKey(bits int) error {
	if bits == 0 {
		bits = DEFAULT_KEY_BITS
	} else if bits < 12 {
		return errors.New("generate key error: invalid bits")
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	publicKey := &privateKey.PublicKey
	m.Key.privateKey = privateKey
	m.Key.publicKey = publicKey
	return nil
}

// 加密
func (m *KeyManager) Encrypt(plainText []byte, label []byte) (string, error) {
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, m.Key.publicKey, plainText, label)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// 解密
func (m *KeyManager) Decrypt(plainText string, label []byte) ([]byte, error) {
	rng := rand.Reader
	ct, err := base64.StdEncoding.DecodeString(plainText)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rng, m.Key.privateKey, ct, label)
}
