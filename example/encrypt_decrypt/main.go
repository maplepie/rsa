package main

import (
	"fmt"

	"github.com/maplepie/rsa"
)

func main() {
	r := rsa.New()
	str := []byte("Hello World!")

	err := r.GenerateKey(rsa.ADVANTAGE_KEY_BITS)
	if err != nil {
		fmt.Println(err)
	}

	encrypt, err := r.Encrypt(str, nil)
	if err != nil {
		fmt.Println(err)
	}
	result, err := r.Decrypt(encrypt, nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(result))
}
