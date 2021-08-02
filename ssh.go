package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh"
)

const (
	DEFAULT_SSH_PUBLICFILE  = `id_rsa.pub` // 默认公钥名
	DEFAULT_SSH_PRIVATEFILE = `id_rsa`     // 默认私钥名
)

type SSHKey struct{}

func NewSSHKey() *SSHKey {
	return &SSHKey{}
}

func defaultSSHFile(privateFile string, publicFile string) (string, string) {
	if privateFile == "" {
		privateFile = DEFAULT_SSH_PRIVATEFILE
	}
	if publicFile == "" {
		publicFile = DEFAULT_SSH_PUBLICFILE
	}
	return privateFile, publicFile
}

func (s *SSHKey) Save(key *Key, privateFile string, publicFile string) error {
	privateFile, publicFile = defaultSSHFile(privateFile, publicFile)
	err := s.savePrivateKey(key.privateKey, privateFile)
	if err != nil {
		return err
	}
	err = s.savePublicKey(key.publicKey, publicFile)
	if err != nil {
		return err
	}
	return nil
}

func (s *SSHKey) savePrivateKey(privateKey *rsa.PrivateKey, filename string) error {
	raw := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: raw,
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

func (s *SSHKey) savePublicKey(publicKey *rsa.PublicKey, filename string) error {
	raw, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return err
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	pub := ssh.MarshalAuthorizedKey(raw)
	_, err = file.Write(pub)
	if err != nil {
		return err
	}
	return nil
}

func (s *SSHKey) Load(key *Key, privateFile string, publicFile string) error {
	privateFile, publicFile = defaultSSHFile(privateFile, publicFile)
	err := s.loadPrivateKey(key, privateFile)
	if err != nil {
		return err
	}
	err = s.loadPublicKey(key, publicFile)
	if err != nil {
		return err
	}
	return nil
}

// 从文件读取私钥
func (s *SSHKey) loadPrivateKey(key *Key, filename string) error {

	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	// openssh需要使用下面的函数才能解析，而pem的RSA PRIVAT EKEY可以使用x509.ParsePKCS1PrivateKey和ssh.ParseRawPrivateKey两种
	_privateKey, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return err
	}
	privateKey, ok := _privateKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("privatekey invalid")
	}
	key.privateKey = privateKey
	return nil
}

// 从文件读取公钥
func (s *SSHKey) loadPublicKey(key *Key, filename string) error {
	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return err
	}

	parsedCryptoKey := parsed.(ssh.CryptoPublicKey)

	pubCrypto := parsedCryptoKey.CryptoPublicKey()

	publicKey, ok := pubCrypto.(*rsa.PublicKey)
	if !ok {
		return errors.New("publickey invalid")
	}
	key.publicKey = publicKey
	return nil
}
