// Key encapsulation TCP client Go example with hybrid ECDH + Kyber KEM
package main

import (
	"bufio"
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

	"github.com/open-quantum-safe/liboqs-go/oqs"

	"crypto/aes"
    "crypto/cipher"
)

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
	if len(os.Args) != 3 {
		fmt.Println("Usage: client_kem <address> <port number>")
		os.Exit(1)
	}
	address := os.Args[1]
	port := os.Args[2]

	fmt.Println("Launching hybrid (ECDH + Kyber KEM) client on", address+":"+port)
	conn, err := net.Dial("tcp", address+":"+port)
	if err != nil {
		log.Fatal(errors.New("client cannot connect to " + address + ":" + port))
	}
	defer conn.Close() // clean up even in case of panic

	// === Receive KEM Name from Server ===
	kemName, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Fatal(errors.New("client cannot receive the KEM name from the server"))
	}
	kemName = kemName[:len(kemName)-1] // remove the '\n'

	// === ECDH Key Exchange ===
	// Generate ECDH key pair
	clientPrivKeyECDH, clientPubXECDH, clientPubYECDH, err := GenerateECDHKeyPair()
	if err != nil {
		log.Fatal("ECDH key generation error:", err)
	}

	// Send client's ECDH public key to the server
	_, err = fmt.Fprintf(conn, "%x %x\n", clientPubXECDH, clientPubYECDH)
	if err != nil {
		log.Fatal("Client failed to send ECDH public key:", err)
	}

	// Receive server's ECDH public key
	var serverPubXECDH, serverPubYECDH big.Int
	_, err = fmt.Fscanf(conn, "%x %x\n", &serverPubXECDH, &serverPubYECDH)
	if err != nil {
		log.Fatal("Client failed to receive ECDH public key from server:", err)
	}

	// Derive ECDH shared secret
	sharedSecretECDH, err := DeriveSharedSecret(clientPrivKeyECDH, &serverPubXECDH, &serverPubYECDH)
	if err != nil {
		log.Fatal("Error deriving ECDH shared secret:", err)
	}
	fmt.Printf("Client ECDH shared secret: %x\n", sharedSecretECDH)

	// === Kyber KEM Key Exchange ===
	// Initialize the KEM client
	client := oqs.KeyEncapsulation{}
	defer client.Clean() // clean up even in case of panic

	if err := client.Init(kemName, nil); err != nil {
		log.Fatal(err)
	}

	// Generate Kyber KEM key pair
	clientPublicKey, err := client.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// Send the client public key to the server
	_, err = conn.Write(clientPublicKey)
	if err != nil {
		log.Fatal(errors.New("client cannot send the public key to the server"))
	}

	// Receive the encapsulated secret (ciphertext) from the server
	ciphertext := make([]byte, client.Details().LengthCiphertext)
	n, err := io.ReadFull(conn, ciphertext)
	if err != nil {
		log.Fatal(err)
	} else if n != client.Details().LengthCiphertext {
		log.Fatal(errors.New("client expected to read " +
			fmt.Sprintf("%v", client.Details().LengthCiphertext) + " bytes, but instead " +
			"read " + fmt.Sprintf("%v", n)))
	}

	// Decapsulate the secret to obtain the shared secret
	sharedSecretKyber, err := client.DecapSecret(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Client Kyber shared secret: %x\n", sharedSecretKyber)

	// === Combine ECDH and Kyber Shared Secrets (Hybrid) ===
	combinedSharedSecret := sha256.Sum256(append(sharedSecretECDH, sharedSecretKyber...))

	fmt.Printf("\nClient hybrid shared secret:\n% X ... % X\n",
	combinedSharedSecret[0:8], combinedSharedSecret[len(combinedSharedSecret)-8:])

	// Now, using AES encryption as an example
    aesKey := combinedSharedSecret[:32] // Use first 32 bytes for AES-256 key

    // Encrypt a message to send to the server
    block, err := aes.NewCipher(aesKey)
    if err != nil {
        log.Fatal(err)
    }
    
    // Using GCM for authenticated encryption
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        log.Fatal(err)
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        log.Fatal(err)
    }
    plaintext := []byte("Hello from the client!")
    codedtext := gcm.Seal(nonce, nonce, plaintext, nil)

    // Send encrypted message to server
    conn.Write(codedtext)

	// Read the server response
	codedtext = make([]byte, 1024) // Example size
	n2, err := conn.Read(codedtext)
	if err != nil {
		log.Fatal(err)
	}

	block, err = aes.NewCipher(aesKey)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err = cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonceSize := gcm.NonceSize()
	nonce, codedtext = codedtext[:nonceSize], codedtext[nonceSize:n2]
	
	plaintext, err = gcm.Open(nil, nonce, codedtext, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted message from server: %s\n", plaintext)
}
