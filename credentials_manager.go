package forwardproxy

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

type CredentialsManager struct {
	authCredentials [][]byte // slice with base64-encoded credentials
}

var cm = new(CredentialsManager)

const _keyFilePath = "./key.pem"
const _certFilePath = "./cert.pem"

//read credentials from local config file
func readCredentials() {

}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func generateKeyAndCert() (keyFilePath string, certFilePath string) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %s", err)
	}
	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	ioutil.WriteFile(_certFilePath, out.Bytes(), 0644)
	out.Reset()
	pem.Encode(out, pemBlockForKey(priv))
	ioutil.WriteFile(_keyFilePath, out.Bytes(), 0644)

	keyFilePath = _keyFilePath
	certFilePath = _certFilePath
	return
}

func handleAddRequest(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handle add request")
}

func handleDelRequest(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handle del request")
}

// listen on manager port to add or del user
func StartListen() {
	adminPort := GetAdminPort()
	keyPath, certPath := generateKeyAndCert()
	listenAddr := fmt.Sprintf(":%d", adminPort)
	http.HandleFunc("/add", handleAddRequest)
	http.HandleFunc("/del", handleDelRequest)
	err := http.ListenAndServeTLS(listenAddr, certPath, keyPath, nil)
	if err != nil {
		fmt.Println("listen on port :", listenAddr, " error:", err.Error())
	}
}

// check if credentials is correct
func CheckCredentialsEx(cd []byte) error {
	for _, creds := range cm.authCredentials {
		if subtle.ConstantTimeCompare(creds, cd) == 1 {
			return nil
		}
	}
	return errors.New("Invalid credentials")
}
