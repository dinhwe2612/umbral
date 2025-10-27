package umbralprecgo

import (
	"bytes"
	"testing"
	"time"
)

// BenchmarkStreamEncryptionDecryption benchmarks the complete encryption and decryption workflow
func BenchmarkStreamEncryptionDecryption(b *testing.B) {
	// Generate key pair once
	privateKeyBytes, publicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create test data chunks
	chunkSizes := []int{1024, 64 * 1024, 256 * 1024} // 1KB, 64KB, 256KB

	for _, chunkSize := range chunkSizes {
		b.Run(createBenchName(chunkSize), func(b *testing.B) {
			testData := make([]byte, chunkSize)
			for i := range testData {
				testData[i] = byte(i)
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Create encryptor once per iteration
				encryptor, capsuleBytes, err := CreateStreamEncryptor(publicKeyBytes)
				if err != nil {
					b.Fatal(err)
				}

				// Encrypt
				encrypted, err := encryptor.EncryptChunk(testData)
				if err != nil {
					b.Fatal(err)
				}
				encryptor.Free()

				// Decrypt
				decryptor, err := CreateStreamDecryptorOriginal(privateKeyBytes, capsuleBytes)
				if err != nil {
					b.Fatal(err)
				}

				decrypted, err := decryptor.DecryptChunk(encrypted)
				if err != nil {
					b.Fatal(err)
				}

				// Verify
				if !bytes.Equal(testData, decrypted) {
					b.Fatal("Decryption mismatch")
				}

				decryptor.Free()
			}
		})
	}
}

// BenchmarkStreamEncryptorCreation benchmarks the cost of creating stream encryptors
func BenchmarkStreamEncryptorCreation(b *testing.B) {
	_, publicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		encryptor, _, err := CreateStreamEncryptor(publicKeyBytes)
		if err != nil {
			b.Fatal(err)
		}
		encryptor.Free()
	}
}

// BenchmarkStreamDecryptorCreation benchmarks the cost of creating stream decryptors
func BenchmarkStreamDecryptorCreation(b *testing.B) {
	privateKeyBytes, publicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create capsule once
	encryptor, capsuleBytes, err := CreateStreamEncryptor(publicKeyBytes)
	if err != nil {
		b.Fatal(err)
	}
	encryptor.Free()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		decryptor, err := CreateStreamDecryptorOriginal(privateKeyBytes, capsuleBytes)
		if err != nil {
			b.Fatal(err)
		}
		decryptor.Free()
	}
}

// BenchmarkConcurrentChunkEncryption benchmarks concurrent chunk encryption
func BenchmarkConcurrentChunkEncryption(b *testing.B) {
	_, publicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		b.Fatalf("Failed to generate key pair: %v", err)
	}

	chunkSize := 64 * 1024 // 64KB
	testData := make([]byte, chunkSize)
	for i := range testData {
		testData[i] = byte(i)
	}

	b.ResetTimer()
	b.ReportAllocs()

	encryptor, _, err := CreateStreamEncryptor(publicKeyBytes)
	if err != nil {
		b.Fatal(err)
	}
	defer encryptor.Free()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := encryptor.EncryptChunk(testData)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestStreamEncryptionThroughput measures encryption throughput for streaming use case
func TestStreamEncryptionThroughput(t *testing.T) {
	_, publicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create encryptor once
	encryptor, capsuleBytes, err := CreateStreamEncryptor(publicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create stream encryptor: %v", err)
	}
	defer encryptor.Free()

	t.Logf("Capsule size: %d bytes", len(capsuleBytes))

	// Test different chunk sizes
	chunkSizes := []int{1024, 10 * 1024, 64 * 1024, 256 * 1024}
	numChunks := 100

	for _, chunkSize := range chunkSizes {
		t.Run(createBenchName(chunkSize), func(t *testing.T) {
			chunk := make([]byte, chunkSize)
			for i := range chunk {
				chunk[i] = byte(i)
			}

			start := time.Now()
			var totalEncryptedLen int64

			for i := 0; i < numChunks; i++ {
				encrypted, err := encryptor.EncryptChunk(chunk)
				if err != nil {
					t.Fatal(err)
				}
				totalEncryptedLen += int64(len(encrypted))
			}

			elapsed := time.Since(start)
			throughput := float64(totalEncryptedLen) / elapsed.Seconds() / 1024 / 1024 // MB/s

			t.Logf("Chunk size: %d bytes", chunkSize)
			t.Logf("Total chunks: %d", numChunks)
			t.Logf("Total encrypted data: %d bytes", totalEncryptedLen)
			t.Logf("Time elapsed: %v", elapsed)
			t.Logf("Encryption throughput: %.2f MB/s", throughput)
			t.Logf("Average chunk encryption time: %v", elapsed/time.Duration(numChunks))
		})
	}
}

// TestStreamDecryptionThroughput measures decryption throughput
func TestStreamDecryptionThroughput(t *testing.T) {
	privateKeyBytes, publicKeyBytes, err := GenerateEthereumKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create encryptor and encrypt chunks
	encryptor, capsuleBytes, err := CreateStreamEncryptor(publicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to create stream encryptor: %v", err)
	}
	defer encryptor.Free()

	chunkSize := 64 * 1024 // 64KB
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i)
	}

	// Encrypt chunks
	numChunks := 100
	encryptedChunks := make([][]byte, numChunks)
	for i := 0; i < numChunks; i++ {
		encrypted, err := encryptor.EncryptChunk(chunk)
		if err != nil {
			t.Fatal(err)
		}
		encryptedChunks[i] = encrypted
	}

	// Create decryptor and measure decryption
	decryptor, err := CreateStreamDecryptorOriginal(privateKeyBytes, capsuleBytes)
	if err != nil {
		t.Fatalf("Failed to create stream decryptor: %v", err)
	}
	defer decryptor.Free()

	start := time.Now()
	var totalDecryptedLen int64

	for i := 0; i < numChunks; i++ {
		decrypted, err := decryptor.DecryptChunk(encryptedChunks[i])
		if err != nil {
			t.Fatal(err)
		}

		// Verify correctness
		if !bytes.Equal(chunk, decrypted) {
			t.Errorf("Chunk %d decryption mismatch", i)
		}

		totalDecryptedLen += int64(len(decrypted))
	}

	elapsed := time.Since(start)
	throughput := float64(totalDecryptedLen) / elapsed.Seconds() / 1024 / 1024 // MB/s

	t.Logf("Chunk size: %d bytes", chunkSize)
	t.Logf("Total chunks: %d", numChunks)
	t.Logf("Total decrypted data: %d bytes", totalDecryptedLen)
	t.Logf("Time elapsed: %v", elapsed)
	t.Logf("Decryption throughput: %.2f MB/s", throughput)
	t.Logf("Average chunk decryption time: %v", elapsed/time.Duration(numChunks))
}

// Helper function to create benchmark names
func createBenchName(bytes int) string {
	switch {
	case bytes < 1024:
		return "1KB"
	case bytes < 64*1024:
		return "64KB"
	default:
		return "256KB"
	}
}
