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
	"encoding/base64"
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
	authCredentials  [][]byte // slice with base64-encoded credentials
	credentialsCount int
	adminUser        string
	adminPwd         string
	lock             sync.Mutex
}

type ClientRequest struct {
	AuthStr string `json:"authstr"`
}

type UserListResponse struct {
	Ret   int      `json:"ret"`
	Users []string `json:"users"`
}

var cm = new(CredentialsManager)

const _keyFilePath = "./key.pem"
const _certFilePath = "./cert.pem"

const _credFilePath = "./.credentials"

//SetAdminUser : set the  user name of  administrator
func SetAdminUser(user string) {
	cm.adminUser = user
}

// SetAdminPwd : set the password of administrator
func SetAdminPwd(pwd string) {
	cm.adminPwd = pwd
}

// AddCredentialsEx :  add credentials from external
func AddCredentialsEx(cred []byte) {
	fmt.Printf("add credentials from cmd : %s \n", cred)
	cm.init()
	cm.readCredentials()
	cm.addCredential(cred)
	cm.save()
}

func (c *CredentialsManager) checkAdmin(req *http.Request) error {
	userLen := len(c.adminUser)
	pwdLen := len(c.adminPwd)
	if userLen <= 0 || pwdLen <= 0 {
		return nil
	}
	authStr := base64.StdEncoding.EncodeToString([]byte(c.adminUser + ":" + c.adminPwd))
	reqAuthStr := req.Header.Get("Proxy-Authorization")
	if strings.Compare(authStr, reqAuthStr) == 0 {
		return nil
	}
	fmt.Println("check admin error , reqAuth:", reqAuthStr, " auth str:", authStr)
	return errors.New("auth str is incorrect")
}

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
	if len(bytes) == 0 {
		return
	}
	readstr := string(bytes)
	lines := strings.Split(readstr, "\n")

	for _, v := range lines {
		if len(v) > 0 {
			c.addCredential([]byte(v))
		}

	}
}

func (c *CredentialsManager) save() {
	fmt.Println("save credentials count :", c.credentialsCount)
	f := checkFileAndCreate()
	f.Truncate(0)
	if c.credentialsCount > 0 {
		for _, v := range c.authCredentials {
			if v != nil && len(v) > 0 {
				line := string(v) + "\n"
				fmt.Printf("save cred : %s", line)
				f.Write([]byte(line))
				f.Sync()
			} else {
				break
			}
		}
	}
	f.Close()
	fmt.Println("save credentials done")
}

func (c *CredentialsManager) init() {
	if c.authCredentials == nil {
		c.authCredentials = [][]byte{}
	}
	c.credentialsCount = 0
}

func (c *CredentialsManager) addCredential(cred []byte) {
	fmt.Printf("addCredential %s \n", cred)
	c.lock.Lock()
	defer func() { c.lock.Unlock() }()
	shouldAdd := true
	for _, v := range c.authCredentials {
		if subtle.ConstantTimeCompare(v, cred) == 1 {
			shouldAdd = false
			break
		}
	}
	if shouldAdd {
		c.credentialsCount++
		added := false
		for i := range c.authCredentials {
			if c.authCredentials[i] == nil {
				c.authCredentials[i] = cred
				added = true
			}
		}
		if !added {
			c.authCredentials = append(c.authCredentials, cred)
		}
	}
	fmt.Println("addCredential done")
}

func (c *CredentialsManager) delCredential(cred []byte) {
	c.lock.Lock()
	defer func() { fmt.Println("unlock"); c.lock.Unlock() }()
	for i, v := range c.authCredentials {
		if subtle.ConstantTimeCompare(cred, v) == 1 {
			c.authCredentials[i] = nil
			c.credentialsCount--
			break
		}
	}
}

func (c *CredentialsManager) getCredentials() [][]byte {
	c.lock.Lock()
	defer func() { fmt.Println("unlock"); c.lock.Unlock() }()
	return c.authCredentials
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
		SerialNumber: big.NewInt(0),
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
	err1 := cm.checkAdmin(req)
	if err1 != nil {
		w.WriteHeader(200)
		w.Write([]byte("{ret:-1}"))
		return
	}
	addReq := ClientRequest{}
	err := json.NewDecoder(req.Body).Decode(&addReq)
	if err != nil {
		fmt.Printf("decode add request failed %s \n", err.Error())
		return
	}
	authStr := addReq.AuthStr
	authBytes := []byte(authStr)
	cm.addCredential(authBytes)
	cm.save()
	writeData := []byte("{ret : 0}")
	w.WriteHeader(200)
	w.Write(writeData)
}

func handleDelRequest(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handle del request")
	err1 := cm.checkAdmin(req)
	if err1 != nil {
		w.WriteHeader(200)
		w.Write([]byte("{ret:-1}"))
		return
	}
	delReq := ClientRequest{}
	err := json.NewDecoder(req.Body).Decode(&delReq)
	if err != nil {
		fmt.Printf("decode del request failed %s \n", err.Error())
		return
	}
	authBytes := []byte(delReq.AuthStr)
	cm.delCredential(authBytes)
	cm.save()
	writeData := []byte("{ret : 0}")
	w.WriteHeader(200)
	w.Write(writeData)
}

func handleGetUserListRequest(w http.ResponseWriter, req *http.Request) {
	fmt.Println("handle list request")
	err1 := cm.checkAdmin(req)
	if err1 != nil {
		w.WriteHeader(200)
		w.Write([]byte("{ret:-1}"))
		return
	}

	creds := cm.getCredentials()
	res := UserListResponse{}
	res.Ret = 0
	if cm.credentialsCount > 0 {
		for _, v := range creds {
			if v == nil || len(v) == 0 {
				continue
			}
			fmt.Printf("append str : %s \n", v)
			res.Users = append(res.Users, string(v))
		}
	}

	bytes, err := json.Marshal(&res)
	if err != nil {
		fmt.Printf("marshal json obj failed %s \n", err.Error())
		return
	}
	fmt.Printf("write bytes len : %d  %s \n", len(bytes), bytes)
	w.Header().Set("Content-Type", "application/json;charset=utf-8")
	w.WriteHeader(200)
	w.Write(bytes)
}

// StartListen : listen on manager port to add or del user
func StartListen() {
	adminPort := GetAdminPort()
	keyPath, certPath := generateKeyAndCert()
	listenAddr := fmt.Sprintf(":%d", adminPort)
	http.HandleFunc("/add", handleAddRequest)
	http.HandleFunc("/del", handleDelRequest)
	http.HandleFunc("/list", handleGetUserListRequest)
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
