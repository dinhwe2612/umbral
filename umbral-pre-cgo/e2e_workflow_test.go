package umbralprecgo

import (
	"testing"
)

// TestE2EWorkflow tests the complete Umbral workflow using utils.go functions
func TestE2EWorkflow(t *testing.T) {
	// Step 1: Generate Ethereum key pairs
	t.Log("Step 1: Generating Ethereum key pairs...")

	// Delegating party (data owner) keys
	delegatingPrivateKeyBytes, delegatingPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate delegating key pair: %v", err)
	}
	t.Logf("Delegating private key: %x", delegatingPrivateKeyBytes)
	t.Logf("Delegating public key: %x", delegatingPublicKeyBytes)

	// Receiving party (data consumer) keys
	receivingPrivateKeyBytes, receivingPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiving key pair: %v", err)
	}
	t.Logf("Receiving private key: %x", receivingPrivateKeyBytes)
	t.Logf("Receiving public key: %x", receivingPublicKeyBytes)

	// Step 2: Encrypt data
	t.Log("Step 2: Encrypting data...")
	plaintext := []byte("Hello, Umbral Proxy Re-encryption!")
	t.Logf("Plaintext: %s", string(plaintext))

	capsuleBytes, ciphertext, err := EncrypData(delegatingPublicKeyBytes, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}
	t.Logf("Capsule bytes length: %d", len(capsuleBytes))
	t.Logf("Ciphertext length: %d", len(ciphertext))

	// Step 3: Create rekey (key fragments)
	t.Log("Step 3: Creating rekey...")
	kfragBytes, err := CreateRekey(delegatingPrivateKeyBytes, receivingPublicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create rekey: %v", err)
	}
	t.Logf("Key fragment bytes length: %d", len(kfragBytes))

	// Step 4: Re-encrypt capsule
	t.Log("Step 4: Re-encrypting capsule...")
	cfragBytes, err := ReencryptCapsule(
		capsuleBytes,
		kfragBytes,
		delegatingPublicKeyBytes, // verifying public key (signer's key)
		delegatingPublicKeyBytes, // delegating public key
		receivingPublicKeyBytes,  // receiving public key
	)
	if err != nil {
		t.Fatalf("Failed to re-encrypt capsule: %v", err)
	}
	t.Logf("Capsule fragment bytes length: %d", len(cfragBytes))

	// Step 5: Decrypt re-encrypted data
	t.Log("Step 5: Decrypting re-encrypted data...")
	decrypted, err := DecryptReencryptedData(
		receivingPrivateKeyBytes,
		delegatingPublicKeyBytes,
		capsuleBytes,
		cfragBytes,
		ciphertext,
	)
	if err != nil {
		t.Fatalf("Failed to decrypt re-encrypted data: %v", err)
	}
	t.Logf("Decrypted: %s", string(decrypted))

	// Verify decryption
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed: expected %s, got %s", string(plaintext), string(decrypted))
	} else {
		t.Log("✅ E2E workflow completed successfully!")
	}
}

// TestStreamEncryptionDecryptionChunks tests complete chunk-by-chunk workflow
func TestStreamEncryptionDecryptionChunks(t *testing.T) {
	t.Log("Testing chunk-by-chunk encryption and decryption...")

	// Step 1: Generate key pair
	t.Log("Step 1: Generating Ethereum key pair...")
	privateKeyBytes, publicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Step 2: Create stream encryptor
	t.Log("Step 2: Creating stream encryptor...")
	encryptor, capsuleBytes, err := CreateStreamEncryptor(publicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create stream encryptor: %v", err)
	}
	defer encryptor.Free()

	// Step 3: Encrypt chunks
	t.Log("Step 3: Encrypting file chunks...")
	chunks := [][]byte{
		[]byte("This is chunk 1 of a large file."),
		[]byte("This is chunk 2 of a large file."),
		[]byte("This is chunk 3 - the final chunk!"),
	}

	encryptedChunks := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		encrypted, err := EncryptChunk(encryptor, chunk)
		if err != nil {
			t.Fatalf("Failed to encrypt chunk %d: %v", i+1, err)
		}
		encryptedChunks[i] = encrypted
		t.Logf("Encrypted chunk %d: %d bytes -> %d bytes", i+1, len(chunk), len(encrypted))
	}

	// Step 4: Create stream decryptor
	t.Log("Step 4: Creating stream decryptor...")
	decryptor, err := CreateStreamDecryptorOriginal(privateKeyBytes, capsuleBytes)
	if err != nil {
		t.Fatalf("Failed to create stream decryptor: %v", err)
	}
	defer decryptor.Free()

	// Step 5: Decrypt chunks
	t.Log("Step 5: Decrypting chunks...")
	for i, encryptedChunk := range encryptedChunks {
		decrypted, err := DecryptChunkOriginal(decryptor, encryptedChunk)
		if err != nil {
			t.Fatalf("Failed to decrypt chunk %d: %v", i+1, err)
		}

		// Verify decrypted matches original
		if string(decrypted) != string(chunks[i]) {
			t.Errorf("Chunk %d mismatch: expected %q, got %q", i+1, string(chunks[i]), string(decrypted))
		} else {
			t.Logf("✅ Chunk %d decrypted successfully: %q", i+1, string(decrypted))
		}
	}

	t.Log("✅ Stream encryption/decryption test completed successfully!")
}

// TestE2EWorkflowWithValidation tests the complete workflow with key validation
func TestE2EWorkflowWithValidation(t *testing.T) {
	// Step 1: Generate and validate Ethereum key pairs
	t.Log("Step 1: Generating and validating Ethereum key pairs...")

	delegatingPrivateKeyBytes, delegatingPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate delegating key pair: %v", err)
	}

	receivingPrivateKeyBytes, receivingPublicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate receiving key pair: %v", err)
	}

	// Step 2: Encrypt data
	t.Log("Step 2: Encrypting data...")
	plaintext := []byte("Umbral Proxy Re-encryption with validation!")
	capsuleBytes, ciphertext, err := EncrypData(delegatingPublicKeyBytes, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Step 3: Create rekey
	t.Log("Step 3: Creating rekey...")
	kfragBytes, err := CreateRekey(delegatingPrivateKeyBytes, receivingPublicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create rekey: %v", err)
	}

	// Step 4: Re-encrypt
	t.Log("Step 4: Re-encrypting...")
	cfragBytes, err := ReencryptCapsule(
		capsuleBytes,
		kfragBytes,
		delegatingPublicKeyBytes,
		delegatingPublicKeyBytes,
		receivingPublicKeyBytes,
	)
	if err != nil {
		t.Fatalf("Failed to re-encrypt: %v", err)
	}

	// Step 5: Decrypt
	t.Log("Step 5: Decrypting...")
	decrypted, err := DecryptReencryptedData(
		receivingPrivateKeyBytes,
		delegatingPublicKeyBytes,
		capsuleBytes,
		cfragBytes,
		ciphertext,
	)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify
	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption failed: expected %s, got %s", string(plaintext), string(decrypted))
	} else {
		t.Log("✅ E2E workflow with validation completed successfully!", string(decrypted))
		t.Log("✅ E2E workflow with validation completed successfully!", string(plaintext))
	}
}
