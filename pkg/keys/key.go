package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// NewKeyPair : creates a new key pair
func NewRSAKeyPair(name string) {
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	caPrivKeyPEM := new(bytes.Buffer)

	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	ioutil.WriteFile("./keys/"+name+".key", caPrivKeyPEM.Bytes(), 0755)
}

// NewECDSAKeyPair : creates new elliptic curve key pair
func NewECDSAKeyPair(name string) {
	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		fmt.Println(err)
	}

	der, _ := x509.MarshalECPrivateKey(privKey)

	privKeyPEM := new(bytes.Buffer)

	pem.Encode(privKeyPEM, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})

	ioutil.WriteFile("./keys/"+name+".key", privKeyPEM.Bytes(), 0755)
}
