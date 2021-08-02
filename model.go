package rsa

import "crypto/rsa"

type Reader interface {
	Load(key *Key, privateFile string, publicFile string) (err error)
}

type Writer interface {
	Save(key *Key, privateFile string, publicFile string) (err error)
}

type Key struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}
