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

	sign, err := r.Sign(str)
	if err != nil {
		fmt.Println(err)
	}
	err = r.Verify(str, sign)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("Vertify")
	}
}
