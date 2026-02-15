// This is free and unencumbered software released into the public domain.

// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.

// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

// For more information, please refer to <https://unlicense.org>

// Code adapted from https://gist.github.com/shaneutt/5e1995295cff6721c89a71d13a71c251#file-ca_and_cert_golang_demo-go

// Big thanks to Shane Utt! :)

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

	caPrivateKey, err := x509.ParseCertificate(caPrivateKeyPEM.Bytes)
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

	return leafCertAsPem, leafPrivateKeyAsPem, nil
}