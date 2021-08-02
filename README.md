# rsa

RSA module

## Install

```bash
go get github.com/maplepie/rsa
```

## What is RSA

RSA is designed to encrypt or decrypt data. It supports:

* encrypt or decrypt data
* sign and verify data
* reading from `PEM`, `SSH-RSA`, `OpenSSH` key files
* writing to `PEM`, `SSH-RSA` key files
* generate key

## Example

### Simple

Here is an example of simple encrypt/decrypt data.

```go
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
```

you can use label to encrypt your data, and you should use the same label to decrypt your data which you had encrypt.

```go
r := rsa.New()
str := []byte("Hello World!")

err := r.GenerateKey(rsa.ADVANTAGE_KEY_BITS)
if err != nil {
    fmt.Println(err)
}

// add label
label := []byte("your message id")

encrypt, err := r.Encrypt(str, label)
if err != nil {
    fmt.Println(err)
}
result, err := r.Decrypt(encrypt, label)
if err != nil {
    fmt.Println(err)
}
fmt.Println(string(result))
```

### Reading key from files

```go
r := rsa.New()
str := []byte("Hello World!")

p := rsa.NewPemKey() // read key use pem method
// p := rsa.NewSSHKey() // read key use ssh-rsa method

r.SetReader(p)
// load file form file path
err := r.Load("private.pem", "public.pem")
if err != nil {
    fmt.Println(err)
}

encrypt, err := r.Encrypt(str, nil)
if err != nil {
    fmt.Println(err)
}
fmt.Println(encrypt)
```

### Write key to files

```go
r := rsa.New()

err := r.GenerateKey(rsa.ADVANTAGE_KEY_BITS)
if err != nil {
	fmt.Println(err)
}

p := rsa.NewPemKey() // save key use pem method
// p := rsa.NewSSHKey() // save key use ssh-rsa method

r.SetWriter(p)

// save file to file path
err = r.Save("private.pem", "public.pem")
if err != nil {
	fmt.Println(err)
}
```

### Translate

translate pem type to ssh-rsa type, or reverse.

```go
r := rsa.New()

p1 := rsa.NewPemKey() // read key use pem method
p2 := rsa.NewSSHKey() // save key use ssh-rsa method

r.SetReader(p1)
r.SetWriter(p2)

err = r.Load("private.pem", "public.pem")
if err != nil {
    fmt.Println(err)
}

// save file to file path
err = r.Save("id_rsa", "id_rsa.pub")
if err != nil {
	fmt.Println(err)
}
```

### Advantage

if you want to use custom reader/writer, you just need to implement the interface of `Reader` or `Writer`.

```go
type Reader interface {
	Load(key *Key, privateFile string, publicFile string) (err error)
}

type Writer interface {
	Save(key *Key, privateFile string, publicFile string) (err error)
}
```