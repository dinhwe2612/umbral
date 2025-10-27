package main

import (
	"fmt"
	"log"

	umbralprecgo "github.com/dinhwe2612/umbra/umbral-pre-cgo"
)

func main() {
	// Generate Ethereum key pairs
	delegatingPrivateKey, delegatingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	receivingPrivateKey, receivingPublicKey, err := umbralprecgo.GenerateEthereumKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt data
	plaintext := []byte("Hello, Umbral!")
	capsuleBytes, ciphertext, err := umbralprecgo.EncrypData(delegatingPublicKey, plaintext)
	if err != nil {
		log.Fatal(err)
	}

	// Create rekey
	kfragBytes, err := umbralprecgo.CreateRekey(delegatingPrivateKey, receivingPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Re-encrypt
	cfragBytes, err := umbralprecgo.ReencryptCapsule(
		capsuleBytes,
		kfragBytes,
		delegatingPublicKey, // verifying key
		delegatingPublicKey, // delegating key
		receivingPublicKey,  // receiving key
	)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt
	decrypted, err := umbralprecgo.DecryptReencryptedData(
		receivingPrivateKey,
		delegatingPublicKey,
		capsuleBytes,
		cfragBytes,
		ciphertext,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))
}
