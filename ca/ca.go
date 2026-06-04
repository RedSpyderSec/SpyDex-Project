package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// LoadOrGenerateCA carga caCertFile/caKeyFile y genera los ficheros si no existen.
// Devuelve un tls.Certificate listo para usar con goproxy.TLSConfigFromCA.
func LoadOrGenerateCA(caCertFile, caKeyFile string) (*tls.Certificate, error) {
	// Si existen, los cargamos
	if _, err := os.Stat(caCertFile); err == nil {
		if _, err := os.Stat(caKeyFile); err == nil {
			cert, err := tls.LoadX509KeyPair(caCertFile, caKeyFile)
			if err != nil {
				return nil, fmt.Errorf("loading CA: %w", err)
			}
			// Parseamos el leaf para que goproxy tenga la info completa
			if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
				return nil, fmt.Errorf("parsing CA leaf: %w", err)
			}
			return &cert, nil
		}
	}

	// Si no existen, generamos una CA auto-firmada (solo para desarrollo)
	// En producción, deberías crear la CA fuera y protegerla.
	fmt.Fprintf(os.Stderr, "CA not found in %s/%s, generating self-signed CA (DEV only)\n", caCertFile, caKeyFile)

	// Crear clave RSA
	// Nota: en producción real usarías una clave fuera de código y protegida.
	// Aquí simplificamos con una clave autogenerada en memoria.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}

	// Crear plantilla de certificado
	notBefore := time.Now()
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10 años

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: "SpyDex CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA cert: %w", err)
	}

	// Guardar en ficheros
	certFile, err := os.Create(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("creating cert file: %w", err)
	}
	defer certFile.Close()
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyFile, err := os.Create(caKeyFile)
	if err != nil {
		return nil, fmt.Errorf("creating key file: %w", err)
	}
	defer keyFile.Close()
	pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Cargar de nuevo para tener el leaf
	return LoadOrGenerateCA(caCertFile, caKeyFile)
}