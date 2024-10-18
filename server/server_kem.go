// Key encapsulation TCP server Go example with hybrid ECDH + Kyber KEM
package main

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Usage: server_kem <port number> [KEM name (optional)]")
		os.Exit(1)
	}
	port := os.Args[1]
	kemName := "Kyber512"
	if len(os.Args) > 2 {
		kemName = os.Args[2]
	}

	log.SetOutput(os.Stdout) // log to stdout instead of the default stderr
	fmt.Println("Launching hybrid (ECDH +", kemName, ") server on port", port)

	// Pre-initialize Kyber KEM for logging details
	kem := oqs.KeyEncapsulation{}
	if err := kem.Init(kemName, nil); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n\n", kem.Details())
	kem.Clean()

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatal(err)
	}

	// Listen indefinitely (until explicitly stopped, e.g., with CTRL+C in UNIX)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
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
	if err != nil {
		log.Fatal(err)
	} else if n != server.Details().LengthCiphertext {
		log.Fatal(errors.New("server expected to write " + fmt.Sprintf("%v", server.
			Details().LengthCiphertext) + " bytes, but instead wrote " + fmt.Sprintf("%v", n)))
	}

	fmt.Printf("Server Kyber shared secret: %x\n", sharedSecretKyber)

	// === Combine ECDH and Kyber Shared Secrets (Hybrid) ===
	combinedSharedSecret := sha256.Sum256(append(sharedSecretECDH, sharedSecretKyber...))

	log.Printf("\nConnection #%d - server hybrid shared secret:\n% X ... % X\n\n",
		counter.Val(), combinedSharedSecret[0:8],
		combinedSharedSecret[len(combinedSharedSecret)-8:])

	// Use combined key to decrypt incoming messages
    aesKey := combinedSharedSecret[:32] // Use first 32 bytes for AES-256

	// Read the incoming ciphertext
    codedtext := make([]byte, 1024) // Example size
    n2, err := conn.Read(codedtext)
    if err != nil {
        log.Fatal(err)
    }

    block, err := aes.NewCipher(aesKey)
    if err != nil {
        log.Fatal(err)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Fatal(err)
    }

    nonceSize := gcm.NonceSize()
    nonce, codedtext := codedtext[:nonceSize], codedtext[nonceSize:n2]
    
    plaintext, err := gcm.Open(nil, nonce, codedtext, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Decrypted message from client: %s\n", plaintext)

	// Encrypt a response to send to the client
	block, err = aes.NewCipher(aesKey)
	if err != nil {
		log.Fatal(err)
	}
	
	// Using GCM for authenticated encryption
	gcm, err = cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}
	plaintext = []byte("Ola do servidor BR!")
	codedtext = gcm.Seal(nonce, nonce, plaintext, nil)

	// Send encrypted message to server
	conn.Write(codedtext)

	// Increment the connection number
	counter.Add()
}
