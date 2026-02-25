
package scamjamtls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
	"fmt"

	"github.com/rs/zerolog"

)

// KeyPairWithPin returns PEM encoded Certificate and Key along with an SKPI
// fingerprint of the public key.
func GetRootCa(logger *zerolog.Logger, certOrgName string) (caCertAsPem []byte, caPrivateKeyAsPem []byte, err error) {
	
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{
			//CommonName:    "127.0.0.3", 
			Organization:  []string{certOrgName},
			Country:       []string{"US"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(2, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Error().Msg("Error generating RSA private key pair for CA!" + err.Error())
		return nil, nil, err
	}


	caPrivateKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		logger.Error().Msg("Error creating CA x.509!" + err.Error())
		return nil, nil, err
	}


	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return caPEM.Bytes(), caPrivateKeyPEM.Bytes(), nil
}


func GetLeaf(logger *zerolog.Logger, certOrgName string, caCertAsBytes []byte, caPrivateKeyAsBytes []byte,) (leafCertAsPem []byte, leafPrivateKeyAsPem []byte, err error) {

	caCertPEM, restOfCaCertPEM := pem.Decode(caCertAsBytes)
	switch {
	case caCertPEM == nil:
		err = fmt.Errorf("Failed to decode root CA cert from bytes! (PEM was empty)")
		logger.Error().Err(err)
		return nil, nil, err
	case caCertPEM.Type != "CERTIFICATE":
		err = fmt.Errorf("Failed to decode root CA cert from bytes! (PEM is not a certificate)")
		logger.Error().Err(err)
		return nil, nil, err
	case restOfCaCertPEM != nil:
		logger.Warn().Msg("Found extra data after root CA cert: " +  string(restOfCaCertPEM[:]) + " Will try to continue.")
	}


	caPrivateKeyPEM, restOfCAPrivateKeyPEM := pem.Decode(caPrivateKeyAsBytes)
	switch {
	case caPrivateKeyPEM == nil:
		err = fmt.Errorf("Failed to decode root CA private key from bytes! (PEM was empty)")
		logger.Error().Err(err)
		return nil, nil, err
	case caPrivateKeyPEM.Type != "RSA PRIVATE KEY":
		err = fmt.Errorf("Failed to decode root CA private key from bytes! (PEM is not a private key)")
		logger.Error().Err(err)
		return nil, nil, err
	case restOfCAPrivateKeyPEM != nil:
		logger.Warn().Msg("Found extra data after root CA private key: " +  string(restOfCAPrivateKeyPEM[:]) + " Will try to continue.")
	}

	caCert, err := x509.ParseCertificate(caCertPEM.Bytes)
    if err != nil {
		logger.Error().Err(err).Msg("Failed to decode root CA cert from PEM!")
		return nil, nil, err
    }

	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyPEM.Bytes)
	if err != nil {
		logger.Error().Err(err).Msg("Failed to decode root CA private key from PEM!")
		return nil, nil, err
    }



	leafCertDetails := &x509.Certificate{
	SerialNumber: big.NewInt(200),
	Subject: pkix.Name{
		//CommonName:    "127.0.0.3",
		Organization:  []string{certOrgName},
		Country:       []string{"US"},
	},
	IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	NotBefore:    time.Now(),
	NotAfter:     time.Now().AddDate(10, 0, 0),
	SubjectKeyId: []byte{1, 2, 3, 4, 6},
	ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	KeyUsage:     x509.KeyUsageDigitalSignature,
}

	leafCertPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		logger.Error().Msg("Error generating RSA private key pair for server cert!" + err.Error())
		return nil, nil, err
	}

	leafCertBytes, err := x509.CreateCertificate(rand.Reader, leafCertDetails, caCert, &leafCertPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		logger.Error().Msg("Error creating server x.509!" + err.Error())
		return nil, nil, err
	}

	leafCertPEM := new(bytes.Buffer)
	pem.Encode(leafCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafCertBytes,
	})

	leafCertPrivateKeyPEM := new(bytes.Buffer)
	pem.Encode(leafCertPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(leafCertPrivateKey),
	})

	return leafCertPEM.Bytes(), leafCertPrivateKeyPEM.Bytes(), nil
}