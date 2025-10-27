package umbralprecgo

/*
#cgo LDFLAGS: -L./lib -lumbral_pre -ldl -lm
#cgo darwin LDFLAGS: -framework Security -framework Foundation
#cgo windows LDFLAGS: -luser32 -lkernel32 -ladvapi32
#cgo linux LDFLAGS: -ldl -lm
#cgo CFLAGS: -I../umbral-pre/src
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    int32_t code;
    uint8_t* message;
    size_t message_len;
} UmbralError;

typedef struct {
    uint8_t* data;
    size_t len;
} ByteBuffer;

typedef void* SecretKeyPtr;
typedef void* PublicKeyPtr;
typedef void* SignerPtr;
typedef void* CapsulePtr;
typedef void* KeyFragPtr;
typedef void* VerifiedKeyFragPtr;
typedef void* CapsuleFragPtr;
typedef void* VerifiedCapsuleFragPtr;
typedef void* StreamEncryptorPtr;
typedef void* StreamDecryptorPtr;
typedef void* DEMPtr;

typedef intptr_t (*ReadCallback)(void* ctx, uint8_t* buf, size_t buf_len);
typedef int32_t (*WriteCallback)(void* ctx, const uint8_t* data, size_t data_len);

// Memory management
void umbral_byte_buffer_free(ByteBuffer buf);
void umbral_error_free(UmbralError err);

// Key generation
SecretKeyPtr umbral_secret_key_random();
int32_t umbral_secret_key_from_bytes(
    const uint8_t* bytes,
    size_t bytes_len,
    SecretKeyPtr* sk_out,
    UmbralError* error_out
);
void umbral_secret_key_free(SecretKeyPtr sk);
PublicKeyPtr umbral_secret_key_public_key(SecretKeyPtr sk);
void umbral_public_key_free(PublicKeyPtr pk);
int32_t umbral_public_key_from_bytes(
    const uint8_t* bytes,
    size_t bytes_len,
    PublicKeyPtr* pk_out,
    UmbralError* error_out
);
ByteBuffer umbral_public_key_to_bytes(PublicKeyPtr pk);
ByteBuffer umbral_secret_key_to_bytes(SecretKeyPtr sk);

// Capsule
int32_t umbral_capsule_from_bytes(
    const uint8_t* bytes,
    size_t bytes_len,
    CapsulePtr* capsule_out,
    UmbralError* error_out
);
void umbral_capsule_free(CapsulePtr capsule);
ByteBuffer umbral_capsule_to_bytes_simple(CapsulePtr capsule);
ByteBuffer umbral_capsule_to_bytes(CapsulePtr capsule);
void umbral_capsule_verify(CapsulePtr capsule, UmbralError* error_out);
int umbral_capsule_from_public_key(PublicKeyPtr pk, CapsulePtr* capsule_out, ByteBuffer* key_seed_out, UmbralError* error_out);
int umbral_capsule_from_bytes(const uint8_t* bytes, size_t bytes_len, CapsulePtr* capsule_out, UmbralError* error_out);
int umbral_key_frag_from_bytes(const uint8_t* bytes, size_t bytes_len, KeyFragPtr* kfrag_out, UmbralError* error_out);
ByteBuffer umbral_key_frag_to_bytes(KeyFragPtr kfrag);
ByteBuffer umbral_capsule_frag_to_bytes(VerifiedCapsuleFragPtr vcfrag);
int32_t umbral_capsule_frag_from_bytes(const uint8_t* bytes, size_t bytes_len, VerifiedCapsuleFragPtr* vcfrag_out, UmbralError* error_out);

// Signer
SignerPtr umbral_signer_new(SecretKeyPtr sk);
void umbral_signer_free(SignerPtr signer);
PublicKeyPtr umbral_signer_verifying_key(SignerPtr signer);

// Encryption/Decryption
int32_t umbral_encrypt(
    PublicKeyPtr pk,
    const uint8_t* plaintext,
    size_t plaintext_len,
    CapsulePtr* capsule_out,
    ByteBuffer* ciphertext_out,
    UmbralError* error_out
);

int32_t umbral_decrypt_original(
    SecretKeyPtr sk,
    CapsulePtr capsule,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    ByteBuffer* plaintext_out,
    UmbralError* error_out
);

void umbral_capsule_free(CapsulePtr capsule);

// Key Fragment generation
int32_t umbral_generate_kfrags(
    SecretKeyPtr delegating_sk,
    PublicKeyPtr receiving_pk,
    SignerPtr signer,
    size_t threshold,
    size_t shares,
    _Bool sign_delegating_key,
    _Bool sign_receiving_key,
    VerifiedKeyFragPtr** kfrags_out,
    UmbralError* error_out
);

void umbral_verified_kfrag_free(VerifiedKeyFragPtr kfrag);
KeyFragPtr umbral_verified_kfrag_unverify(VerifiedKeyFragPtr kfrag);
void umbral_kfrag_free(KeyFragPtr kfrag);

int32_t umbral_kfrag_verify(
    KeyFragPtr kfrag,
    PublicKeyPtr verifying_pk,
    PublicKeyPtr delegating_pk,
    PublicKeyPtr receiving_pk,
    VerifiedKeyFragPtr* verified_kfrag_out,
    UmbralError* error_out
);

// Re-encryption
int32_t umbral_reencrypt(
    CapsulePtr capsule,
    VerifiedKeyFragPtr verified_kfrag,
    VerifiedCapsuleFragPtr* verified_cfrag_out,
    UmbralError* error_out
);

void umbral_verified_cfrag_free(VerifiedCapsuleFragPtr cfrag);
CapsuleFragPtr umbral_verified_cfrag_unverify(VerifiedCapsuleFragPtr cfrag);
void umbral_cfrag_free(CapsuleFragPtr cfrag);

int32_t umbral_cfrag_verify(
    CapsuleFragPtr cfrag,
    CapsulePtr capsule,
    PublicKeyPtr verifying_pk,
    PublicKeyPtr delegating_pk,
    PublicKeyPtr receiving_pk,
    VerifiedCapsuleFragPtr* verified_cfrag_out,
    UmbralError* error_out
);

// Decrypt re-encrypted
int32_t umbral_decrypt_reencrypted(
    SecretKeyPtr receiving_sk,
    PublicKeyPtr delegating_pk,
    CapsulePtr capsule,
    const VerifiedCapsuleFragPtr* verified_cfrags,
    size_t verified_cfrags_len,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    ByteBuffer* plaintext_out,
    UmbralError* error_out
);

ReadCallback get_read_callback();
WriteCallback get_write_callback();

// Stream processing
int32_t umbral_stream_encryptor_new(
    PublicKeyPtr pk,
    StreamEncryptorPtr* encryptor_out,
    UmbralError* error_out
);

void umbral_stream_encryptor_free(StreamEncryptorPtr encryptor);
CapsulePtr umbral_stream_encryptor_capsule(StreamEncryptorPtr encryptor);

int32_t umbral_stream_encryptor_encrypt_chunk(
    StreamEncryptorPtr encryptor,
    const uint8_t* chunk,
    size_t chunk_len,
    ByteBuffer* ciphertext_out,
    UmbralError* error_out
);

int32_t umbral_stream_encryptor_process(
    StreamEncryptorPtr encryptor,
    ReadCallback read_callback,
    WriteCallback write_callback,
    void* ctx,
    UmbralError* error_out
);

int32_t umbral_stream_decryptor_new_original(
    SecretKeyPtr sk,
    CapsulePtr capsule,
    StreamDecryptorPtr* decryptor_out,
    UmbralError* error_out
);

void umbral_stream_decryptor_free(StreamDecryptorPtr decryptor);

int32_t umbral_stream_decryptor_decrypt_chunk(
    StreamDecryptorPtr decryptor,
    const uint8_t* encrypted_chunk,
    size_t encrypted_chunk_len,
    ByteBuffer* plaintext_out,
    UmbralError* error_out
);

int32_t umbral_stream_decryptor_new_reencrypted(
    SecretKeyPtr receiving_sk,
    PublicKeyPtr delegating_pk,
    CapsulePtr capsule,
    const VerifiedCapsuleFragPtr* verified_cfrags,
    size_t verified_cfrags_len,
    StreamDecryptorPtr* decryptor_out,
    UmbralError* error_out
);

void umbral_stream_decryptor_free(StreamDecryptorPtr decryptor);

int32_t umbral_stream_decryptor_process(
    StreamDecryptorPtr decryptor,
    ReadCallback read_callback,
    WriteCallback write_callback,
    void* ctx,
    UmbralError* error_out
);

// Capsule seed key extraction
int32_t umbral_capsule_open_reencrypted(
    SecretKeyPtr receiving_sk,
    PublicKeyPtr delegating_pk,
    CapsulePtr capsule,
    const VerifiedCapsuleFragPtr* verified_cfrags,
    size_t verified_cfrags_len,
    ByteBuffer* key_seed_out,
    UmbralError* error_out
);

// DEM (symmetric encryption) functions
DEMPtr umbral_dem_new(const uint8_t* key_seed, size_t key_seed_len);
void umbral_dem_free(DEMPtr dem);
int32_t umbral_dem_decrypt(
    DEMPtr dem,
    const uint8_t* ciphertext,
    size_t ciphertext_len,
    const uint8_t* authenticated_data,
    size_t authenticated_data_len,
    ByteBuffer* plaintext_out,
    UmbralError* error_out
);

*/
import "C"
import (
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

// SecretKey represents a secret key for encryption/decryption
type SecretKey struct {
	ptr C.SecretKeyPtr
}

// PublicKey represents a public key for encryption
type PublicKey struct {
	ptr C.PublicKeyPtr
}

// Signer is used to sign key fragments and capsule fragments
type Signer struct {
	ptr C.SignerPtr
}

// Capsule encapsulates a symmetric key for DEM encryption
type Capsule struct {
	ptr C.CapsulePtr
}

// KeyFrag is an unverified key fragment
type KeyFrag struct {
	ptr C.KeyFragPtr
}

// VerifiedKeyFrag is a verified key fragment
type VerifiedKeyFrag struct {
	ptr C.VerifiedKeyFragPtr
}

// CapsuleFrag is an unverified capsule fragment
type CapsuleFrag struct {
	ptr C.CapsuleFragPtr
}

// VerifiedCapsuleFrag is a verified capsule fragment
type VerifiedCapsuleFrag struct {
	ptr C.VerifiedCapsuleFragPtr
}

// Error represents an error from the Umbral library
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("umbral error %d: %s", e.Code, e.Message)
}

// GenerateSecretKey generates a random secret key
func GenerateSecretKey() *SecretKey {
	ptr := C.umbral_secret_key_random()
	sk := &SecretKey{ptr: ptr}
	runtime.SetFinalizer(sk, (*SecretKey).Free)
	return sk
}

// GenerateSecretKeyFromBytes creates a secret key from bytes
func GenerateSecretKeyFromBytes(bytes []byte) (*SecretKey, error) {
	var skOut C.SecretKeyPtr
	var errorOut C.UmbralError

	bytesPtr := (*C.uint8_t)(C.CBytes(bytes))
	defer C.free(unsafe.Pointer(bytesPtr))

	result := C.umbral_secret_key_from_bytes(
		bytesPtr,
		C.size_t(len(bytes)),
		&skOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	sk := &SecretKey{ptr: skOut}
	runtime.SetFinalizer(sk, (*SecretKey).Free)
	return sk, nil
}

func GeneratePublicKeyFromBytes(bytes []byte) (*PublicKey, error) {
	var pkOut C.PublicKeyPtr
	var errorOut C.UmbralError

	bytesPtr := (*C.uint8_t)(C.CBytes(bytes))
	defer C.free(unsafe.Pointer(bytesPtr))

	result := C.umbral_public_key_from_bytes(
		bytesPtr,
		C.size_t(len(bytes)),
		&pkOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	pk := &PublicKey{ptr: pkOut}
	runtime.SetFinalizer(pk, (*PublicKey).Free)
	return pk, nil
}

func (sk *SecretKey) ToBytes() ([]byte, error) {
	bytesOut := C.umbral_secret_key_to_bytes(sk.ptr)
	defer C.umbral_byte_buffer_free(bytesOut)

	return C.GoBytes(unsafe.Pointer(bytesOut.data), C.int(bytesOut.len)), nil
}

func (pk *PublicKey) ToBytes() ([]byte, error) {
	bytesOut := C.umbral_public_key_to_bytes(pk.ptr)
	defer C.umbral_byte_buffer_free(bytesOut)

	return C.GoBytes(unsafe.Pointer(bytesOut.data), C.int(bytesOut.len)), nil
}

func (sk *SecretKey) Free() {
	if sk.ptr != nil {
		C.umbral_secret_key_free(sk.ptr)
		sk.ptr = nil
	}
}

// PublicKey returns the public key corresponding to this secret key
func (sk *SecretKey) PublicKey() *PublicKey {
	ptr := C.umbral_secret_key_public_key(sk.ptr)
	pk := &PublicKey{ptr: ptr}
	runtime.SetFinalizer(pk, (*PublicKey).Free)
	return pk
}

func (pk *PublicKey) Free() {
	if pk.ptr != nil {
		C.umbral_public_key_free(pk.ptr)
		pk.ptr = nil
	}
}

// NewSigner creates a new signer from a secret key
func NewSigner(sk *SecretKey) *Signer {
	ptr := C.umbral_signer_new(sk.ptr)
	signer := &Signer{ptr: ptr}
	runtime.SetFinalizer(signer, (*Signer).Free)
	return signer
}

func (s *Signer) Free() {
	if s.ptr != nil {
		C.umbral_signer_free(s.ptr)
		s.ptr = nil
	}
}

// VerifyingKey returns the public key used for verification
func (s *Signer) VerifyingKey() *PublicKey {
	ptr := C.umbral_signer_verifying_key(s.ptr)
	pk := &PublicKey{ptr: ptr}
	runtime.SetFinalizer(pk, (*PublicKey).Free)
	return pk
}

func (c *Capsule) Free() {
	if c.ptr != nil {
		C.umbral_capsule_free(c.ptr)
		c.ptr = nil
	}
}

func (kf *KeyFrag) Free() {
	if kf.ptr != nil {
		C.umbral_kfrag_free(kf.ptr)
		kf.ptr = nil
	}
}

func (vkf *VerifiedKeyFrag) Free() {
	if vkf.ptr != nil {
		C.umbral_verified_kfrag_free(vkf.ptr)
		vkf.ptr = nil
	}
}

func (cf *CapsuleFrag) Free() {
	if cf.ptr != nil {
		C.umbral_cfrag_free(cf.ptr)
		cf.ptr = nil
	}
}

func (vcf *VerifiedCapsuleFrag) Free() {
	if vcf.ptr != nil {
		C.umbral_verified_cfrag_free(vcf.ptr)
		vcf.ptr = nil
	}
}

// encrypt encrypts the plaintext with the public key
func umbralEncrypt(pk *PublicKey, plaintext []byte) (*Capsule, []byte, error) {
	var capsuleOut C.CapsulePtr
	var ciphertextOut C.ByteBuffer
	var errorOut C.UmbralError

	plaintextPtr := (*C.uint8_t)(C.CBytes(plaintext))
	defer C.free(unsafe.Pointer(plaintextPtr))

	result := C.umbral_encrypt(
		pk.ptr,
		plaintextPtr,
		C.size_t(len(plaintext)),
		&capsuleOut,
		&ciphertextOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	capsule := &Capsule{ptr: capsuleOut}
	runtime.SetFinalizer(capsule, (*Capsule).Free)

	ciphertext := C.GoBytes(unsafe.Pointer(ciphertextOut.data), C.int(ciphertextOut.len))
	C.umbral_byte_buffer_free(ciphertextOut)

	return capsule, ciphertext, nil
}

// umbralDecryptOriginal decrypts ciphertext using the original secret key
func umbralDecryptOriginal(sk *SecretKey, capsule *Capsule, ciphertext []byte) ([]byte, error) {
	var plaintextOut C.ByteBuffer
	var errorOut C.UmbralError

	ciphertextPtr := (*C.uint8_t)(C.CBytes(ciphertext))
	defer C.free(unsafe.Pointer(ciphertextPtr))

	result := C.umbral_decrypt_original(
		sk.ptr,
		capsule.ptr,
		ciphertextPtr,
		C.size_t(len(ciphertext)),
		&plaintextOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	plaintext := C.GoBytes(unsafe.Pointer(plaintextOut.data), C.int(plaintextOut.len))
	C.umbral_byte_buffer_free(plaintextOut)

	return plaintext, nil
}

// generateKFrags generates key fragments for re-encryption
func generateKFrags(delegatingSK *SecretKey, receivingPK *PublicKey, signer *Signer, threshold, shares int, signDelegatingKey, signReceivingKey bool) ([]*VerifiedKeyFrag, error) {
	var kfragsOut *C.VerifiedKeyFragPtr
	var errorOut C.UmbralError

	result := C.umbral_generate_kfrags(
		delegatingSK.ptr,
		receivingPK.ptr,
		signer.ptr,
		C.size_t(threshold),
		C.size_t(shares),
		C._Bool(signDelegatingKey),
		C._Bool(signReceivingKey),
		&kfragsOut,
		&errorOut,
	)

	if result < 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	// Convert C array to Go slice
	kfragPtrSlice := (*[1 << 30]C.VerifiedKeyFragPtr)(unsafe.Pointer(kfragsOut))[:shares:shares]
	kfrags := make([]*VerifiedKeyFrag, shares)
	for i := 0; i < shares; i++ {
		kfrags[i] = &VerifiedKeyFrag{ptr: kfragPtrSlice[i]}
		runtime.SetFinalizer(kfrags[i], (*VerifiedKeyFrag).Free)
	}

	// Free the array itself (not the elements)
	C.free(unsafe.Pointer(kfragsOut))

	return kfrags, nil
}

// unverify returns an unverified version of the key fragment
func (vkf *VerifiedKeyFrag) unverify() *KeyFrag {
	ptr := C.umbral_verified_kfrag_unverify(vkf.ptr)
	kf := &KeyFrag{ptr: ptr}
	runtime.SetFinalizer(kf, (*KeyFrag).Free)
	return kf
}

// verify verifies a key fragment
func (kf *KeyFrag) verify(verifyingPK *PublicKey, delegatingPK, receivingPK *PublicKey) (*VerifiedKeyFrag, error) {
	var verifiedOut C.VerifiedKeyFragPtr
	var errorOut C.UmbralError

	var delegatingPtr, receivingPtr C.PublicKeyPtr
	if delegatingPK != nil {
		delegatingPtr = delegatingPK.ptr
	}
	if receivingPK != nil {
		receivingPtr = receivingPK.ptr
	}

	result := C.umbral_kfrag_verify(
		kf.ptr,
		verifyingPK.ptr,
		delegatingPtr,
		receivingPtr,
		&verifiedOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	vkf := &VerifiedKeyFrag{ptr: verifiedOut}
	runtime.SetFinalizer(vkf, (*VerifiedKeyFrag).Free)
	return vkf, nil
}

// reencrypt re-encrypts a capsule using a verified key fragment
func reencrypt(capsule *Capsule, vkf *VerifiedKeyFrag) (*VerifiedCapsuleFrag, error) {
	var vcfragOut C.VerifiedCapsuleFragPtr
	var errorOut C.UmbralError

	result := C.umbral_reencrypt(
		capsule.ptr,
		vkf.ptr,
		&vcfragOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	vcf := &VerifiedCapsuleFrag{ptr: vcfragOut}
	runtime.SetFinalizer(vcf, (*VerifiedCapsuleFrag).Free)
	return vcf, nil
}

// unverify returns an unverified version of the capsule fragment
func (vcf *VerifiedCapsuleFrag) unverify() *CapsuleFrag {
	ptr := C.umbral_verified_cfrag_unverify(vcf.ptr)
	cf := &CapsuleFrag{ptr: ptr}
	runtime.SetFinalizer(cf, (*CapsuleFrag).Free)
	return cf
}

// verify verifies a capsule fragment
func (cf *CapsuleFrag) verify(capsule *Capsule, verifyingPK, delegatingPK, receivingPK *PublicKey) (*VerifiedCapsuleFrag, error) {
	var verifiedOut C.VerifiedCapsuleFragPtr
	var errorOut C.UmbralError

	result := C.umbral_cfrag_verify(
		cf.ptr,
		capsule.ptr,
		verifyingPK.ptr,
		delegatingPK.ptr,
		receivingPK.ptr,
		&verifiedOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	vcf := &VerifiedCapsuleFrag{ptr: verifiedOut}
	runtime.SetFinalizer(vcf, (*VerifiedCapsuleFrag).Free)
	return vcf, nil
}

// decryptReencrypted decrypts ciphertext using verified capsule fragments
func decryptReencrypted(receivingSK *SecretKey, delegatingPK *PublicKey, capsule *Capsule, vcfrags []*VerifiedCapsuleFrag, ciphertext []byte) ([]byte, error) {
	var plaintextOut C.ByteBuffer
	var errorOut C.UmbralError

	// Convert Go slice to C array
	cfragPtrs := make([]C.VerifiedCapsuleFragPtr, len(vcfrags))
	for i, vcf := range vcfrags {
		cfragPtrs[i] = vcf.ptr
	}

	ciphertextPtr := (*C.uint8_t)(C.CBytes(ciphertext))
	defer C.free(unsafe.Pointer(ciphertextPtr))

	var cfragArrayPtr *C.VerifiedCapsuleFragPtr
	if len(cfragPtrs) > 0 {
		cfragArrayPtr = &cfragPtrs[0]
	}

	result := C.umbral_decrypt_reencrypted(
		receivingSK.ptr,
		delegatingPK.ptr,
		capsule.ptr,
		cfragArrayPtr,
		C.size_t(len(vcfrags)),
		ciphertextPtr,
		C.size_t(len(ciphertext)),
		&plaintextOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	plaintext := C.GoBytes(unsafe.Pointer(plaintextOut.data), C.int(plaintextOut.len))
	C.umbral_byte_buffer_free(plaintextOut)

	return plaintext, nil
}

// ============================================================================
// Stream encryption/decryption
// ============================================================================

// StreamEncryptorGo wraps the C stream encryptor
type StreamEncryptorGo struct {
	ptr C.StreamEncryptorPtr
}

// StreamDecryptorGo wraps the C stream decryptor
type StreamDecryptorGo struct {
	ptr C.StreamDecryptorPtr
}

// streamContext holds reader/writer for callbacks
type streamContext struct {
	reader io.Reader
	writer io.Writer
	err    error
}

//export goReadCallbackBridge
func goReadCallbackBridge(ctx unsafe.Pointer, buf *C.uint8_t, bufLen C.size_t) C.intptr_t {
	// Cast context pointer to streamContext
	context := (*streamContext)(ctx)

	// Check if there's already an error
	if context.err != nil {
		return -1
	}

	// Convert C buffer to Go slice safely
	if bufLen == 0 {
		return 0
	}

	// Create a safe slice from the C buffer
	goBuf := (*[1 << 30]byte)(unsafe.Pointer(buf))[:bufLen:bufLen]

	// Read data from the Go reader
	n, err := context.reader.Read(goBuf)

	// Handle errors
	if err != nil {
		if err == io.EOF {
			// End of stream - return 0 to signal completion
			return 0
		}
		// Other errors - store and return error
		context.err = err
		return -1
	}

	// Return number of bytes read
	return C.intptr_t(n)
}

//export goWriteCallbackBridge
func goWriteCallbackBridge(ctx unsafe.Pointer, data *C.uint8_t, dataLen C.size_t) C.int32_t {
	// Cast context pointer to streamContext
	context := (*streamContext)(ctx)

	// Check if there's already an error
	if context.err != nil {
		return -1
	}

	// Handle empty data
	if dataLen == 0 {
		return 0
	}

	// Convert C data to Go bytes safely
	goData := C.GoBytes(unsafe.Pointer(data), C.int(dataLen))

	// Write data to the Go writer
	_, err := context.writer.Write(goData)

	// Handle write errors
	if err != nil {
		context.err = err
		return -1
	}

	// Success
	return 0
}

// NewStreamEncryptorGo creates a new stream encryptor
func NewStreamEncryptorGo(pk *PublicKey) (*StreamEncryptorGo, error) {
	var encryptorOut C.StreamEncryptorPtr
	var errorOut C.UmbralError

	result := C.umbral_stream_encryptor_new(
		pk.ptr,
		&encryptorOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	enc := &StreamEncryptorGo{ptr: encryptorOut}
	runtime.SetFinalizer(enc, (*StreamEncryptorGo).free)
	return enc, nil
}

func (se *StreamEncryptorGo) free() {
	if se.ptr != nil {
		C.umbral_stream_encryptor_free(se.ptr)
		se.ptr = nil
	}
}

// Free explicitly releases resources associated with the stream encryptor
func (se *StreamEncryptorGo) Free() {
	se.free()
}

// Capsule returns the capsule associated with this stream encryptor
func (se *StreamEncryptorGo) Capsule() *Capsule {
	if se.ptr == nil {
		return nil
	}
	capsulePtr := C.umbral_stream_encryptor_capsule(se.ptr)
	if capsulePtr == nil {
		return nil
	}
	capsule := &Capsule{ptr: capsulePtr}
	runtime.SetFinalizer(capsule, (*Capsule).Free)
	return capsule
}

// EncryptChunk encrypts a single chunk of data
func (se *StreamEncryptorGo) EncryptChunk(chunk []byte) ([]byte, error) {
	var ciphertextOut C.ByteBuffer
	var errorOut C.UmbralError

	chunkPtr := (*C.uint8_t)(C.CBytes(chunk))
	defer C.free(unsafe.Pointer(chunkPtr))

	result := C.umbral_stream_encryptor_encrypt_chunk(
		se.ptr,
		chunkPtr,
		C.size_t(len(chunk)),
		&ciphertextOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	ciphertext := C.GoBytes(unsafe.Pointer(ciphertextOut.data), C.int(ciphertextOut.len))
	C.umbral_byte_buffer_free(ciphertextOut)

	return ciphertext, nil
}

// encryptStream encrypts data from reader and writes to writer
// This makes ONLY ONE call to Rust, which then handles all chunks via callbacks
func (se *StreamEncryptorGo) encryptStream(reader io.Reader, writer io.Writer) error {
	var errorOut C.UmbralError

	context := &streamContext{
		reader: reader,
		writer: writer,
	}

	// Lấy con trỏ hàm từ C "trampoline"
	readCb := C.get_read_callback()
	writeCb := C.get_write_callback()

	result := C.umbral_stream_encryptor_process(
		se.ptr,
		readCb,
		writeCb,
		unsafe.Pointer(context),
		&errorOut,
	)

	if context.err != nil {
		return context.err
	}

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return &Error{Code: int(errorOut.code), Message: msg}
	}

	return nil
}

// NewStreamDecryptorOriginal creates a stream decryptor for original key
func NewStreamDecryptorOriginal(sk *SecretKey, capsule *Capsule) (*StreamDecryptorGo, error) {
	var decryptorOut C.StreamDecryptorPtr
	var errorOut C.UmbralError

	result := C.umbral_stream_decryptor_new_original(
		sk.ptr,
		capsule.ptr,
		&decryptorOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	dec := &StreamDecryptorGo{ptr: decryptorOut}
	runtime.SetFinalizer(dec, (*StreamDecryptorGo).free)
	return dec, nil
}

// NewStreamDecryptorReencrypted creates a stream decryptor for re-encrypted data
func NewStreamDecryptorReencrypted(receivingSK *SecretKey, delegatingPK *PublicKey, capsule *Capsule, vcfrags []*VerifiedCapsuleFrag) (*StreamDecryptorGo, error) {
	var decryptorOut C.StreamDecryptorPtr
	var errorOut C.UmbralError

	cfragPtrs := make([]C.VerifiedCapsuleFragPtr, len(vcfrags))
	for i, vcf := range vcfrags {
		cfragPtrs[i] = vcf.ptr
	}

	var cfragArrayPtr *C.VerifiedCapsuleFragPtr
	if len(cfragPtrs) > 0 {
		cfragArrayPtr = &cfragPtrs[0]
	}

	result := C.umbral_stream_decryptor_new_reencrypted(
		receivingSK.ptr,
		delegatingPK.ptr,
		capsule.ptr,
		cfragArrayPtr,
		C.size_t(len(vcfrags)),
		&decryptorOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	dec := &StreamDecryptorGo{ptr: decryptorOut}
	runtime.SetFinalizer(dec, (*StreamDecryptorGo).free)
	return dec, nil
}

func (sd *StreamDecryptorGo) free() {
	if sd.ptr != nil {
		C.umbral_stream_decryptor_free(sd.ptr)
		sd.ptr = nil
	}
}

// Free explicitly releases resources associated with the stream decryptor
func (sd *StreamDecryptorGo) Free() {
	sd.free()
}

// DecryptChunk decrypts a single encrypted chunk
func (sd *StreamDecryptorGo) DecryptChunk(encryptedChunk []byte) ([]byte, error) {
	var plaintextOut C.ByteBuffer
	var errorOut C.UmbralError

	chunkPtr := (*C.uint8_t)(C.CBytes(encryptedChunk))
	defer C.free(unsafe.Pointer(chunkPtr))

	result := C.umbral_stream_decryptor_decrypt_chunk(
		sd.ptr,
		chunkPtr,
		C.size_t(len(encryptedChunk)),
		&plaintextOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	plaintext := C.GoBytes(unsafe.Pointer(plaintextOut.data), C.int(plaintextOut.len))
	C.umbral_byte_buffer_free(plaintextOut)

	return plaintext, nil
}

// decryptStream decrypts data from reader and writes to writer
// This makes ONLY ONE call to Rust, which then handles all chunks via callbacks
func (sd *StreamDecryptorGo) decryptStream(reader io.Reader, writer io.Writer) error {
	var errorOut C.UmbralError

	context := &streamContext{
		reader: reader,
		writer: writer,
	}

	// Lấy con trỏ hàm từ C "trampoline"
	readCb := C.get_read_callback()
	writeCb := C.get_write_callback()

	result := C.umbral_stream_decryptor_process(
		sd.ptr,
		readCb,
		writeCb,
		unsafe.Pointer(context),
		&errorOut,
	)

	if context.err != nil {
		return context.err
	}

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return &Error{Code: int(errorOut.code), Message: msg}
	}

	return nil
}

// ============================================================================
// Capsule
// ============================================================================

func capsuleToBytes(capsule *Capsule) ([]byte, error) {
	bytesOut := C.umbral_capsule_to_bytes(capsule.ptr)
	defer C.umbral_byte_buffer_free(bytesOut)

	return C.GoBytes(unsafe.Pointer(bytesOut.data), C.int(bytesOut.len)), nil
}

func capsuleFromBytes(bytes []byte) (*Capsule, error) {
	var capsuleOut C.CapsulePtr
	var errorOut C.UmbralError

	result := C.umbral_capsule_from_bytes((*C.uint8_t)(unsafe.Pointer(&bytes[0])), C.size_t(len(bytes)), &capsuleOut, &errorOut)
	defer C.umbral_error_free(errorOut)

	if result != 0 {
		return nil, fmt.Errorf("umbral error %d: %s", errorOut.code, C.GoString((*C.char)(unsafe.Pointer(errorOut.message))))
	}

	capsule := &Capsule{ptr: capsuleOut}
	return capsule, nil
}

func keyFragFromBytes(bytes []byte) (*KeyFrag, error) {
	var kfragOut C.KeyFragPtr
	var errorOut C.UmbralError

	result := C.umbral_key_frag_from_bytes((*C.uint8_t)(unsafe.Pointer(&bytes[0])), C.size_t(len(bytes)), &kfragOut, &errorOut)
	defer C.umbral_error_free(errorOut)

	if result != 0 {
		return nil, fmt.Errorf("umbral error %d: %s", errorOut.code, C.GoString((*C.char)(unsafe.Pointer(errorOut.message))))
	}

	kfrag := &KeyFrag{ptr: kfragOut}
	return kfrag, nil
}

func keyFragToBytes(kfrag *KeyFrag) ([]byte, error) {
	bytesOut := C.umbral_key_frag_to_bytes(kfrag.ptr)
	defer C.umbral_byte_buffer_free(bytesOut)

	return C.GoBytes(unsafe.Pointer(bytesOut.data), C.int(bytesOut.len)), nil
}

func capsuleFragToBytes(vcfrag *VerifiedCapsuleFrag) ([]byte, error) {
	bytesOut := C.umbral_capsule_frag_to_bytes(vcfrag.ptr)
	defer C.umbral_byte_buffer_free(bytesOut)

	return C.GoBytes(unsafe.Pointer(bytesOut.data), C.int(bytesOut.len)), nil
}

func capsuleFragFromBytes(cfragBytes []byte) (*VerifiedCapsuleFrag, error) {
	var vcfragOut C.VerifiedCapsuleFragPtr
	var errorOut C.UmbralError

	result := C.umbral_capsule_frag_from_bytes((*C.uint8_t)(unsafe.Pointer(&cfragBytes[0])), C.size_t(len(cfragBytes)), &vcfragOut, &errorOut)
	defer C.umbral_error_free(errorOut)

	if result != 0 {
		return nil, fmt.Errorf("umbral error %d: %s", errorOut.code, C.GoString((*C.char)(unsafe.Pointer(errorOut.message))))
	}

	vcfrag := &VerifiedCapsuleFrag{ptr: vcfragOut}
	return vcfrag, nil
}

// ============================================================================
// Seed key extraction helper
// ============================================================================

func getSeedKeyFromCapsule(
	receivingSK *SecretKey,
	delegatingPK *PublicKey,
	capsule *Capsule,
	vcfrags []*VerifiedCapsuleFrag,
) ([]byte, error) {
	var keySeedOut C.ByteBuffer
	var errorOut C.UmbralError

	cfragPtrs := make([]C.VerifiedCapsuleFragPtr, len(vcfrags))
	for i, vcf := range vcfrags {
		cfragPtrs[i] = vcf.ptr
	}

	var cfragArrayPtr *C.VerifiedCapsuleFragPtr
	if len(cfragPtrs) > 0 {
		cfragArrayPtr = &cfragPtrs[0]
	}

	result := C.umbral_capsule_open_reencrypted(
		receivingSK.ptr,
		delegatingPK.ptr,
		capsule.ptr,
		cfragArrayPtr,
		C.size_t(len(vcfrags)),
		&keySeedOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	keySeed := C.GoBytes(unsafe.Pointer(keySeedOut.data), C.int(keySeedOut.len))
	C.umbral_byte_buffer_free(keySeedOut)

	return keySeed, nil
}

// ============================================================================
// Symmetric Decryptor
// ============================================================================

// SymmetricDecryptor wraps the C DEM decryptor
type SymmetricDecryptor struct {
	ptr C.DEMPtr
}

// NewSymmetricDecryptor creates a new symmetric decryptor from a seed key
func NewSymmetricDecryptor(seedKeyBytes []byte) (*SymmetricDecryptor, error) {
	if len(seedKeyBytes) == 0 {
		return nil, fmt.Errorf("seed key cannot be empty")
	}

	seedPtr := (*C.uint8_t)(C.CBytes(seedKeyBytes))
	defer C.free(unsafe.Pointer(seedPtr))

	ptr := C.umbral_dem_new(seedPtr, C.size_t(len(seedKeyBytes)))
	if ptr == nil {
		return nil, fmt.Errorf("failed to create DEM decryptor")
	}

	dec := &SymmetricDecryptor{ptr: ptr}
	runtime.SetFinalizer(dec, (*SymmetricDecryptor).free)
	return dec, nil
}

func (sd *SymmetricDecryptor) free() {
	if sd.ptr != nil {
		C.umbral_dem_free(sd.ptr)
		sd.ptr = nil
	}
}

// Free explicitly releases resources associated with the symmetric decryptor
func (sd *SymmetricDecryptor) Free() {
	sd.free()
}

// Decrypt decrypts ciphertext using the symmetric key
// authenticatedData is typically the capsule bytes for non-stream decryption
func (sd *SymmetricDecryptor) DecryptWithCapsule(ciphertext []byte, capsuleBytes []byte) ([]byte, error) {
	var plaintextOut C.ByteBuffer
	var errorOut C.UmbralError

	ciphertextPtr := (*C.uint8_t)(C.CBytes(ciphertext))
	defer C.free(unsafe.Pointer(ciphertextPtr))

	capsulePtr := (*C.uint8_t)(C.CBytes(capsuleBytes))
	defer C.free(unsafe.Pointer(capsulePtr))

	result := C.umbral_dem_decrypt(
		sd.ptr,
		ciphertextPtr,
		C.size_t(len(ciphertext)),
		capsulePtr,
		C.size_t(len(capsuleBytes)),
		&plaintextOut,
		&errorOut,
	)

	if result != 0 {
		defer C.umbral_error_free(errorOut)
		msg := C.GoStringN((*C.char)(unsafe.Pointer(errorOut.message)), C.int(errorOut.message_len))
		return nil, &Error{Code: int(errorOut.code), Message: msg}
	}

	plaintext := C.GoBytes(unsafe.Pointer(plaintextOut.data), C.int(plaintextOut.len))
	C.umbral_byte_buffer_free(plaintextOut)

	return plaintext, nil
}
