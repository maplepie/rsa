package rsa

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

const (
	DEFAULT_PEM_PUBLICFILE  = `public.pem`  // 默认公钥名
	DEFAULT_PEM_PRIVATEFILE = `private.pem` // 默认私钥名
)

type PemKey struct{}

func NewPemKey() *PemKey {
	return &PemKey{}
}

func defaultPemFile(privateFile string, publicFile string) (string, string) {
	if privateFile == "" {
		privateFile = DEFAULT_PEM_PRIVATEFILE
	}
	if publicFile == "" {
		publicFile = DEFAULT_PEM_PUBLICFILE
	}
	return privateFile, publicFile
}

func (p *PemKey) Save(key *Key, privateFile string, publicFile string) error {
	privateFile, publicFile = defaultPemFile(privateFile, publicFile)
	err := p.savePrivateKey(key.privateKey, privateFile)
	if err != nil {
		return err
	}
	err = p.savePublicKey(key.publicKey, publicFile)
	if err != nil {
		return err
	}
	return nil
}

func (p *PemKey) savePrivateKey(privateKey *rsa.PrivateKey, filename string) error {
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

func (p *PemKey) savePublicKey(publicKey *rsa.PublicKey, filename string) error {
	raw, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
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

func (p *PemKey) Load(key *Key, privateFile string, publicFile string) error {
	privateFile, publicFile = defaultPemFile(privateFile, publicFile)
	err := p.loadPrivateKey(key, privateFile)
	if err != nil {
		return err
	}
	err = p.loadPublicKey(key, publicFile)
	if err != nil {
		return err
	}
	return nil
}

// 从文件读取私钥
func (p *PemKey) loadPrivateKey(key *Key, filename string) error {

	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	content := block.Bytes
	privateKey, err := x509.ParsePKCS1PrivateKey(content)
	if err != nil {
		return err
	}
	key.privateKey = privateKey
	return nil
}

// 从文件读取公钥
func (p *PemKey) loadPublicKey(key *Key, filename string) error {

	raw, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	content := block.Bytes
	pub, err := x509.ParsePKIXPublicKey(content)
	if err != nil {
		return err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("publickey invalid")
	}
	key.publicKey = publicKey
	return nil
}
