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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type CredentialsManager struct {
	authCredentials [][]byte // slice with base64-encoded credentials
	adminUser       string
	adminPwd        string
	lock            sync.Mutex
}

type ClientRequest struct {
	AuthStr string `json:"string"`
}

var cm = new(CredentialsManager)

func SetAdminUser(user string) {
	cm.adminUser = user
}

func SetAdminPwd(pwd string) {
	cm.adminPwd = pwd
}

const _keyFilePath = "./key.pem"
const _certFilePath = "./cert.pem"

const _credFilePath = "./.credentials"

//checkFileAndCreate : if file is not exists, create it.  or open it
func checkFileAndCreate() (f *os.File) {
	_, err := os.Stat(_credFilePath)
	if os.IsNotExist(err) {
		file, err2 := os.Create(_credFilePath)
		if err2 != nil {
			fmt.Printf("create credentials file failed %s \n", err.Error())
			return nil
		} else {
			return file
		}
	} else {
		file, err3 := os.OpenFile(_credFilePath, os.O_RDWR, 0666)
		if err3 != nil {
			fmt.Printf("open file error : %s \n", err3.Error())
			return nil
		} else {
			return file
		}
	}
}

//read credentials from local config file
func (c *CredentialsManager) readCredentials() {
	f := checkFileAndCreate()
	defer f.Close()
	bytes, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Printf("read credential file error : %s \n", err.Error())
		return
	}
	readstr := string(bytes)
	lines := strings.Split(readstr, "\n")
	for _, v := range lines {
		c.addCredential([]byte(v))
	}
}

func (c *CredentialsManager) save() {
	c.lock.Lock()
	defer c.lock.Unlock()
	f := checkFileAndCreate()
	f.Truncate(0)
	tmp := make([]byte, 512)
	for _, v := range c.authCredentials {
		if subtle.ConstantTimeCompare(v, tmp) != 1 {
			line := string(v) + "\n"
			f.Write([]byte(line))
		} else {
			break
		}
	}
	f.Close()

}

func (c *CredentialsManager) init() {
	if c.authCredentials == nil {
		c.authCredentials = make([][]byte, 512)
		for i := range c.authCredentials {
			c.authCredentials[i] = make([]byte, 512)
		}
		c.readCredentials()
	}
}

func (c *CredentialsManager) addCredential(cred []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.init()
	var index int
	tmp := make([]byte, 512)
	var shouldAdd bool
	for i, v := range c.authCredentials {
		index = i
		if subtle.ConstantTimeCompare(v, cred) == 1 {
			return
		}
		if subtle.ConstantTimeCompare(v, tmp) == 1 {
			shouldAdd = true
			break
		}
	}
	if shouldAdd {
		copy(c.authCredentials[index], cred)
	} else {
		fmt.Printf("put credentials failed . because of out of 512 count \n")
	}

	c.save()

}

func (c *CredentialsManager) delCredential(cred []byte) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.init()
	tmp := make([]byte, 512)
	for i, v := range c.authCredentials {
		if subtle.ConstantTimeCompare(cred, v) == 1 {
			copy(c.authCredentials[i], tmp) // zero []byte arrays
			break
		}
	}
	c.save()
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
	addReq := ClientRequest{}
	err := json.NewDecoder(req.Body).Decode(&addReq)
	if err != nil {
		fmt.Printf("decode add request failed %s \n", err.Error())
		return
	}
	authStr := addReq.AuthStr
	authBytes := []byte(authStr)
	cm.addCredential(authBytes)
}

func handleDelRequest(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handle del request")
	delReq := ClientRequest{}
	err := json.NewDecoder(req.Body).Decode(&delReq)
	if err != nil {
		fmt.Printf("decode del request failed %s \n", err.Error())
		return
	}
	authBytes := []byte(delReq.AuthStr)
	cm.delCredential(authBytes)
}

// StartListen : listen on manager port to add or del user
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

// CheckCredentialsEx : check if credentials is correct
func CheckCredentialsEx(cd []byte) error {
	for _, creds := range cm.authCredentials {
		if subtle.ConstantTimeCompare(creds, cd) == 1 {
			return nil
		}
	}
	return errors.New("Invalid credentials")
}
