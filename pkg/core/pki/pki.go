package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc64"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aykay76/csp/pkg/models"
)

// NewCA : create a new certificate authority
func NewCA(commonName string, organisation string, organisationalUnit string, province string, locality string, streetAddress string, postalCode string) {
	var root models.Root

	crc64Table := crc64.MakeTable(crc64.ECMA)
	crc64Int := crc64.Checksum([]byte(commonName+organisation+organisationalUnit+province+locality+streetAddress+postalCode), crc64Table)

	root.Identifier = strconv.FormatUint(crc64Int, 16)
	root.Name = commonName
	root.Expiry = time.Now().AddDate(20, 0, 0)
	root.SerialNumber = int64(crc64Int >> 32)

	b, _ := json.Marshal(root)
	ioutil.WriteFile("./cas/"+root.Identifier+".json", b, 0775)

	// TODO: default configuration for some of the below
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(root.SerialNumber),
		Subject: pkix.Name{
			CommonName:    commonName,
			Organization:  []string{organisation},
			Country:       []string{"GB"},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{streetAddress},
			PostalCode:    []string{postalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(20, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		fmt.Println(err)
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	os.Mkdir("./cas/"+root.Identifier, 0755)

	ioutil.WriteFile("./cas/"+root.Identifier+"/root.cer", caPEM.Bytes(), 0755)

	ioutil.WriteFile("./cas/"+root.Identifier+"/root.key", caPrivKeyPEM.Bytes(), 0755)
}

// ListCA : list the CAs that are present
func ListCA() []models.Root {
	var roots []models.Root

	items, _ := ioutil.ReadDir("./cas")
	for _, item := range items {
		if strings.HasSuffix(item.Name(), ".json") {
			var root models.Root
			fileBytes, _ := ioutil.ReadFile("./cas/" + item.Name())
			_ = json.Unmarshal(fileBytes, &root)
			roots = append(roots, root)
		}
	}

	return roots
}

// GetCACert : loads and returns the ca certificate as a string (PEM)
func GetCACert(identifier string) string {
	bytes, _ := ioutil.ReadFile("./cas/" + identifier + "/root.cer")
	return string(bytes)
}

func loadRoot(identifier string) models.Root {
	var root models.Root
	fileBytes, _ := ioutil.ReadFile("./cas/" + identifier + ".json")
	_ = json.Unmarshal(fileBytes, &root)
	return root
}

func saveRoot(root models.Root) {
	b, _ := json.Marshal(root)
	ioutil.WriteFile("./cas/"+root.Identifier+".json", b, 0775)
}

func loadCACert(identifier string) *x509.Certificate {
	filename := "./cas/" + identifier + "/root.cer"

	caBytes, _ := ioutil.ReadFile(filename)

	caCert, _ := pem.Decode(caBytes)
	ca, _ := x509.ParseCertificate(caCert.Bytes)

	return ca
}

func loadCAKey(identifier string) *rsa.PrivateKey {
	filename := "./cas/" + identifier + "/root.key"
	fmt.Println("Reading CA private key from" + filename)
	caPrivKeyBytes, _ := ioutil.ReadFile(filename)
	caPrivKey, _ := pem.Decode(caPrivKeyBytes)
	caPrivateKey, _ := x509.ParsePKCS1PrivateKey(caPrivKey.Bytes)
	return caPrivateKey

}

// SignCSR : signs a csr
func SignCSR(identifier string, csrPEM string) string {
	var idx []models.CertIndex
	indexBytes, _ := ioutil.ReadFile("./cas/" + identifier + "/index.json")
	json.Unmarshal(indexBytes, &idx)

	block, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}

	// TODO: check whether cert has been issued to the subject already, decide what to do if it has
	// revoke and re-sign, return existing or return error??

	// load the CA certificate to get the subject (issuer)
	ca := loadCACert(identifier)

	// load the root information to get the next serial number
	rootInfo := loadRoot(identifier)
	rootInfo.SerialNumber++
	saveRoot(rootInfo)

	// TODO: make validity period configurable
	fmt.Println("Constructing template")
	certTemplate := x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(rootInfo.SerialNumber),
		Issuer:       ca.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour * 365 * 10),
		IsCA:         true,
		// KeyUsage:     x509.KeyUsageDigitalSignature,
		// ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	caPrivateKey := loadCAKey(identifier)

	fmt.Println("Signing certificate")
	certBytes, err := x509.CreateCertificate(rand.Reader, &certTemplate, ca, csr.PublicKey, caPrivateKey)
	if err != nil {
		fmt.Println(err)
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	sn := strconv.FormatInt(rootInfo.SerialNumber, 16)
	ioutil.WriteFile("./cas/"+identifier+"/"+sn+".csr", []byte(csrPEM), 0775)

	ioutil.WriteFile("./cas/"+identifier+"/"+sn+".cer", certPEM.Bytes(), 0775)

	// add to the index and save
	var newidx models.CertIndex
	newidx.Active = true
	newidx.Root = identifier
	newidx.SerialNumber = sn
	newidx.Subject = csr.Subject.String()
	idx = append(idx, newidx)

	newIndexBytes, _ := json.Marshal(idx)
	ioutil.WriteFile("./cas/"+identifier+"/index.json", newIndexBytes, 0775)

	return string(certPEM.String())
}

// RevokeCertificate : revoke a certificate
func RevokeCertificate(identifier string, serialNumber string) {
	var idx []models.CertIndex
	indexBytes, _ := ioutil.ReadFile("./cas/" + identifier + "/index.json")
	json.Unmarshal(indexBytes, &idx)

	// now create CRL to save generate it on the fly when requested
	var revoked []pkix.RevokedCertificate

	for n, i := range idx {
		// if the serial number matches, revoke it
		fmt.Printf("Does %s match %s\n", i.SerialNumber, serialNumber)
		if i.SerialNumber == serialNumber {
			idx[n].Active = false
			idx[n].RevocationTime = time.Now()
		}

		// including the one we just revoked, add all revoked certs to the CRL
		if idx[n].Active == false {
			sn, _ := strconv.ParseInt(i.SerialNumber, 16, 64)
			revoked = append(revoked, pkix.RevokedCertificate{
				SerialNumber:   big.NewInt(sn),
				RevocationTime: i.RevocationTime,
			})
		}
	}

	newIndexBytes, _ := json.Marshal(idx)
	ioutil.WriteFile("./cas/"+identifier+"/index.json", newIndexBytes, 0775)

	// load the CA certificate
	caCER := loadCACert(identifier)
	caKEY := loadCAKey(identifier)

	// TODO: make the expiry configurable
	crlBytes, _ := caCER.CreateCRL(rand.Reader, caKEY, revoked, time.Now(), time.Now().AddDate(0, 0, 7))
	ioutil.WriteFile("./cas/"+identifier+"/crl.der", crlBytes, 0775)
}
