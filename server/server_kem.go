package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"crypto/aes"
    "crypto/cipher"
)

// Counter is a thread-safe counter.
type Counter struct {
	mu  sync.Mutex
	cnt uint64
}

// Add increments the counter.
func (c *Counter) Add() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cnt++
}

// Val retrieves the counter's value.
func (c *Counter) Val() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	cnt := c.cnt
	return cnt
}

// counter is a thread-safe connection counter.
var counter Counter

// GenerateECDHKeyPair generates a private-public key pair for ECDH using the P-256 curve
func GenerateECDHKeyPair() (privKey []byte, pubX, pubY *big.Int, err error) {
	curve := elliptic.P256() // Use the P-256 curve (secp256r1)
	privKey, pubX, pubY, err = elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	return privKey, pubX, pubY, nil
}

// DeriveSharedSecret computes the shared secret using the private key and the other party's public key
func DeriveSharedSecret(privKey []byte, pubX, pubY *big.Int) ([]byte, error) {
	curve := elliptic.P256()
	sharedX, _ := curve.ScalarMult(pubX, pubY, privKey)

	// Use the x-coordinate of the shared point as the shared secret
	sharedSecret := sharedX.Bytes()

	// Optionally, hash the shared secret to derive a fixed-length key
	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil
}

// LoadServerTLSConfig loads the TLS certificates and returns the TLS config for the server
func LoadServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		ClientAuth:				tls.RequireAnyClientCert,
		ClientCAs:				nil,
		Certificates:			[]tls.Certificate{serverCert},
	}

	return tlsConfig, nil
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: server_kem <port number> <server_cert> <server_key> [KEM name (optional)]")
		os.Exit(1)
	}
	port := os.Args[1]
	serverCert := os.Args[2]
	serverKey := os.Args[3]
	// clientCert := os.Args[4]
	kemName := "Kyber512"
	if len(os.Args) == 5 {
		kemName = os.Args[4]
	}

	log.SetOutput(os.Stdout) // log to stdout instead of the default stderr
	fmt.Println("Launching hybrid (ECDH +", kemName, ") server with mTLS on port", port)

	// Load TLS configuration
	tlsConfig, err := LoadServerTLSConfig(serverCert, serverKey)
	if err != nil {
		log.Fatalf("Failed to load TLS config: %v", err)
	}

	// Pre-initialize Kyber KEM for logging details
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(kemName, nil); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n\n", kem.Details())
	kem.Clean()

	// Create a TLS listener using the TLS configuration
	ln, err := tls.Listen("tcp", ":"+port, tlsConfig)
	if err != nil {
		log.Fatalf("Failed to start TLS listener: %v", err)
	}
	defer ln.Close()

	fmt.Printf("Server is listening on port %s with mutual TLS\n\n", port)

	// Listen indefinitely (until explicitly stopped, e.g., with CTRL+C in UNIX)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("Failed to accept connection: %v", err)
		}
		log.Println("Client connected")

		// Assert the connection to be of type *tls.Conn
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Println("Failed to assert connection as TLS")
			conn.Close()
			continue
		}

		// Perform TLS handshake
		err = tlsConn.Handshake()
		if err != nil {
			log.Printf("TLS handshake failed: %v", err)
			conn.Close()
			continue
		}

		// Retrieve the client's certificate
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			clientCert := state.PeerCertificates[0]
			log.Printf("Client Certificate CN: %s\n\n", clientCert.Subject.CommonName)
		} else {
			log.Println("No client certificate provided")
		}

		// Handle connections concurrently
		go handleConnection(conn, kemName)
	}
}

func handleConnection(conn net.Conn, kemName string) {
	defer conn.Close() // clean up even in case of panic

	// Send KEM name to client first
	_, err := fmt.Fprintln(conn, kemName)
	if err != nil {
		log.Fatal(errors.New("server cannot send the KEM name to the client"))
	}
	log.Println("Sent KEM name to client:", kemName)

	// === Classical ECDH Part ===
	serverPrivKeyECDH, serverPubXECDH, serverPubYECDH, err := GenerateECDHKeyPair()
	if err != nil {
		log.Fatal("ECDH key generation error:", err)
	}

	// Send server's ECDH public key (X, Y) to the client
	_, err = fmt.Fprintf(conn, "%x %x\n", serverPubXECDH, serverPubYECDH)
	if err != nil {
		log.Fatal("Server failed to send ECDH public key:", err)
	}

	// Receive client's ECDH public key (X, Y)
	var clientPubXECDH, clientPubYECDH big.Int
	_, err = fmt.Fscanf(conn, "%x %x\n", &clientPubXECDH, &clientPubYECDH)
	if err != nil {
		log.Fatal("Server failed to receive ECDH public key from client:", err)
	}

	// Derive ECDH shared secret
	sharedSecretECDH, err := DeriveSharedSecret(serverPrivKeyECDH, &clientPubXECDH, &clientPubYECDH)
	if err != nil {
		log.Fatal("Error deriving ECDH shared secret:", err)
	}
	fmt.Printf("Server ECDH shared secret: %x\n", sharedSecretECDH)

	// === Post-Quantum Kyber KEM Part ===
	server := oqs.KeyEncapsulation{}
	defer server.Clean() // clean up even in case of panic
	if err := server.Init(kemName, nil); err != nil {
		log.Fatal(err)
	}

	// Read the public key sent by the client
	clientPublicKey := make([]byte, server.Details().LengthPublicKey)
	n, err := io.ReadFull(conn, clientPublicKey)
	if err != nil {
		log.Fatal(err)
	} else if n != server.Details().LengthPublicKey {
		log.Fatal(errors.New("server expected to read " +
			fmt.Sprintf("%v", server.Details().LengthPublicKey) + " bytes, but instead " +
			"read " + fmt.Sprintf("%v", n)))
	}

	// Encapsulate the secret with Kyber
	ciphertext, sharedSecretKyber, err := server.EncapSecret(clientPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Then send ciphertext to client and close the connection
	n, err = conn.Write(ciphertext)
	if err != nil || n != len(ciphertext) {
		log.Fatal("Server failed to send KEM ciphertext to client:", err)
	}

	fmt.Printf("Server Kyber shared secret: %x\n", sharedSecretKyber)

	// === Hybrid Secret Key Establishment (ECDH + Kyber KEM) ===
	// Concatenate both shared secrets
	hybridSecret := append(sharedSecretECDH, sharedSecretKyber...)
	hash := sha256.Sum256(hybridSecret) // hash to create final hybrid key
	finalKey := hash[:]

	// Encrypt data using AES with the final hybrid key
	plaintext := "This is the secret message using hybrid mTLS!"
	ciphertext, err = EncryptAES(finalKey, plaintext)
	if err != nil {
		log.Fatal("Encryption failed:", err)
	}
	fmt.Printf("\nMessage to be sent: %s\n", plaintext)
	fmt.Printf("Encrypted message to be sent: %x\n", ciphertext)

	// Send the encrypted message to the client
	n, err = conn.Write(ciphertext)
	if err != nil || n != len(ciphertext) {
		log.Fatal("Server failed to send encrypted message to client:", err)
	}
	fmt.Println("Encrypted message sent!")

	// Increment connection counter
	counter.Add()
	fmt.Printf("Total connections served: %d\n\n", counter.Val())
}

// EncryptAES encrypts the given plaintext using AES with the provided key
func EncryptAES(key []byte, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Use AES in GCM mode (Authenticated Encryption)
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertext, nil
}
