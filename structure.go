package main

import "time"

type CSR string
type AccountObject struct {
	Status    string   `json:"status,omitempty"`
	Contact   []string `json:"contact"`
	TOSAgreed bool     `json:"termsOfServiceAgreed"`
	Orders    string   `json:"orders,omitempty"`
}

type OrderObject struct {
	Status         string       `json:"status,omitempty"`
	Expires        time.Time    `json:"expires,omitempty"`
	Identifier     []Identifier `json:"identifiers"`
	NotBefore      time.Time    `json:"notBefore"`
	NotAfter       time.Time    `json:"notAfter"`
	Authorizations []string     `json:"authorizations,omitempty"`
	Finalize       string       `json:"finalize,omitempty"`
	Certificate    string       `json:"certificate,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Payload struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type ProtectedHeader struct {
	Algorithm  string `json:"alg"`
	JSONWebKey JWK    `json:"jwk"`
	KeyID      string `json:"kid,omitempty"`
	Nonce      string `json:"nonce,omitempty"` //Fetch It By Sending HEAD Request To API
	URL        string `json:"url"`
}

type JWK struct {
	E       string `json:"e"`
	KeyType string `json:"kty"`
	N       string `json:"n"`
}
