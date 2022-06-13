package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"go.step.sm/crypto/pemutil"
	"io"
	"io/ioutil"
	"log"
	"strconv"
	"strings"
)

func loadKeys(privKeyFilePath, pubKeyFilePath, password string) (*rsa.PrivateKey, error) {
	if privKeyFilePath == "" {
		return nil, fmt.Errorf("FilePath Isn't Valid")
	}

	priv, err := io.ReadFile(privKeyFilePath)

	if err != nil {
		return err
	}

	privPem, _ := pem.Decode(priv)

	var privPEMBytes []byte

	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("RSA key is of the wrong type: Pem Type: %v\n", privPem.Type)
	}

	if password != "" {
		privPEMBytes, err = pemutil.DecryptPEMBlock(privPem, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("invalid password provided probably: %v\n", err)
		}
	} else {
		privPEMBytes = privPem.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS8PrivateKey(privPEMBytes); err != nil {
		return nil, fmt.Errorf("Unable to parse RSA private key: %v\n", err)
	}

	var (
		privateKey *rsa.PrivateKey
		ok         bool
	)

	if privateKey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, errors.New("unable to parse RSA private key")
	}

	// ====================+ PUBLIC KEY PARSING +================================

	pub, err := ioutil.ReadFile(pubKeyFilePath)

	if err != nil {
		return nil, fmt.Errorf("couldn't open public key file: %v\n", err)
	}

	pubPem, _ := pem.Decode(pub)

	if pubPem == nil {
		log.Println("Use `ssh-keygen -f id_rsa.pub -e -m pem > id_rsa.pem` to generate the pem encoding of your RSA public key")
		return nil, errors.New("RSA public key not in pem format")
	}

	if pubPem.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("RSA Key is of the wrong type: " + pubPem.Type)
	}

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		return nil, fmt.Errorf("unable to parse RSA public key")
	}

	pubKey, ok := parsedKey.(*rsa.PublicKey)

	if !ok {
		return nil, errors.New("unable to parse RSA public key")
	}

	privateKey.PublicKey = *pubKey
	return privateKey, nil
}

func GenRSA(bits int) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)

	if err != nil {
		return nil, fmt.Errorf("failed to generate signing keys: %v\n", err)
	}
	return key, nil
}

func payloadify(payload []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(payload), "=")
}

func constructProtectedHeader(nonce, kid string, key *rsa.PrivateKey) ProtectedHeader {
	return ProtectedHeader{
		Algorithm: "RS256",
		Nonce:     nonce,
		JSONWebKey: JWK{
			N:       payloadify(key.PublicKey.N.Bytes()),
			E:       payloadify([]byte(strconv.Itoa(key.PublicKey.E))),
			KeyType: "RSA",
		},
	}
}

func newAccountObject(mail ...string) AccountObject {
	for index, email := range mail {
		if !strings.HasPrefix(email, "mailto:") {
			mail[index] = fmt.Sprintf("mailto:%s", email)
		}
	}
	return AccountObject{
		Contact:   mail,
		TOSAgreed: true,
	}
}
