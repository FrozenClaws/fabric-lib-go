/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package sw

import (
	"hash"
	"reflect"

	"github.com/herumi/bls-go-binary/bls"
	"github.com/hyperledger/fabric-lib-go/bccsp"
	"github.com/hyperledger/fabric-lib-go/common/flogging"
	"github.com/pkg/errors"
)

const (
	BLS12_381 = "BLS12_381"
)

var logger = flogging.MustGetLogger("bccsp_sw")

// CSP provides a generic implementation of the BCCSP interface based
// on wrappers. It can be customized by providing implementations for the
// following algorithm-based wrappers: KeyGenerator, KeyDeriver, KeyImporter,
// Encryptor, Decryptor, Signer, Verifier, Hasher. Each wrapper is bound to a
// golang type representing either an option or a key.
type CSP struct {
	ks bccsp.KeyStore

	KeyGenerators map[reflect.Type]KeyGenerator
	KeyDerivers   map[reflect.Type]KeyDeriver
	KeyImporters  map[reflect.Type]KeyImporter
	Encryptors    map[reflect.Type]Encryptor
	Decryptors    map[reflect.Type]Decryptor
	Signers       map[reflect.Type]Signer
	Verifiers     map[reflect.Type]Verifier
	Hashers       map[reflect.Type]Hasher
}

// blsKey represents a BLS12-381 key
type blsKey struct {
	secretKey  *bls.SecretKey
	publicKey  *bls.PublicKey
	exportable bool
}

// Bytes returns the public key bytes if exportable
func (k *blsKey) Bytes() ([]byte, error) {
	if !k.exportable {
		return nil, errors.New("Key export not allowed")
	}
	if k.publicKey != nil {
		return k.publicKey.Serialize(), nil
	}
	return nil, errors.New("No public key available")
}

// SKI returns the Subject Key Identifier (simplified as first 32 bytes of public key)
func (k *blsKey) SKI() []byte {
	if k.publicKey != nil {
		pubBytes := k.publicKey.Serialize()
		if len(pubBytes) >= 32 {
			return pubBytes[:32]
		}
	}
	return nil
}

// Symmetric returns false for asymmetric keys
func (k *blsKey) Symmetric() bool {
	return false
}

// Private returns true if the key has a private component
func (k *blsKey) Private() bool {
	return k.secretKey != nil
}

// PublicKey returns the public key as a bccsp.Key
func (k *blsKey) PublicKey() (bccsp.Key, error) {
	if k.publicKey == nil {
		return nil, errors.New("No public key available")
	}
	return &blsKey{publicKey: k.publicKey, exportable: k.exportable}, nil
}

// BLS12_381KeyGenerator generates BLS12-381 keys
type BLS12_381KeyGenerator struct{}

// KeyGen generates a BLS12-381 key
func (kg *BLS12_381KeyGenerator) KeyGen(opts bccsp.KeyGenOpts) (bccsp.Key, error) {
	if err := bls.Init(bls.BLS12_381); err != nil {
		return nil, errors.Wrap(err, "Failed to initialize BLS12-381")
	}
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	pub := sec.GetPublicKey()
	return &blsKey{secretKey: &sec, publicKey: pub, exportable: !opts.Ephemeral()}, nil
}

// BLS12_381KeyImporter imports BLS12-381 keys
type BLS12_381KeyImporter struct{}

// KeyImport imports a BLS12-381 key from raw bytes
func (ki *BLS12_381KeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	keyBytes, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material, expected byte array")
	}
	if err := bls.Init(bls.BLS12_381); err != nil {
		return nil, errors.Wrap(err, "Failed to initialize BLS12-381")
	}
	var sec bls.SecretKey
	if err := sec.Deserialize(keyBytes); err != nil {
		return nil, errors.WithMessage(err, "Failed to deserialize BLS12-381 private key")
	}
	pub := sec.GetPublicKey()
	return &blsKey{secretKey: &sec, publicKey: pub, exportable: !opts.Ephemeral()}, nil
}

// BLS12_381Signer signs messages with BLS12-381 keys
type BLS12_381Signer struct{}

// Sign signs a digest with a BLS12-381 key
func (s *BLS12_381Signer) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) ([]byte, error) {
	blsK, ok := k.(*blsKey)
	if !ok || blsK.secretKey == nil {
		return nil, errors.New("Invalid key, expected BLS12-381 private key")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest, cannot be empty")
	}
	sig := blsK.secretKey.SignByte(digest)
	return sig.Serialize(), nil
}

// BLS12_381Verifier verifies BLS12-381 signatures
type BLS12_381Verifier struct{}

// Verify verifies a BLS12-381 signature
func (v *BLS12_381Verifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (bool, error) {
	blsK, ok := k.(*blsKey)
	if !ok || blsK.publicKey == nil {
		return false, errors.New("Invalid key, expected BLS12-381 public key")
	}
	if len(signature) == 0 || len(digest) == 0 {
		return false, errors.New("Invalid signature or digest, cannot be empty")
	}
	var sig bls.Sign
	if err := sig.Deserialize(signature); err != nil {
		return false, errors.WithMessage(err, "Failed to deserialize BLS12-381 signature")
	}
	return sig.VerifyByte(blsK.publicKey, digest), nil
}

func New(keyStore bccsp.KeyStore) (*CSP, error) {
	if keyStore == nil {
		return nil, errors.Errorf("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}

	encryptors := make(map[reflect.Type]Encryptor)
	decryptors := make(map[reflect.Type]Decryptor)
	signers := make(map[reflect.Type]Signer)
	verifiers := make(map[reflect.Type]Verifier)
	hashers := make(map[reflect.Type]Hasher)
	keyGenerators := make(map[reflect.Type]KeyGenerator)
	keyDerivers := make(map[reflect.Type]KeyDeriver)
	keyImporters := make(map[reflect.Type]KeyImporter)

	csp := &CSP{
		ks:            keyStore,
		KeyGenerators: keyGenerators,
		KeyDerivers:   keyDerivers,
		KeyImporters:  keyImporters,
		Encryptors:    encryptors,
		Decryptors:    decryptors,
		Signers:       signers,
		Verifiers:     verifiers,
		Hashers:       hashers,
	}

	// Register BLS12-381 wrappers
	err := csp.AddWrapper(reflect.TypeOf(&bccsp.BLS12_381KeyGenOpts{}), &BLS12_381KeyGenerator{})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to add BLS12-381 key generator")
	}
	err = csp.AddWrapper(reflect.TypeOf(&bccsp.BLS12_381PrivateKeyImportOpts{}), &BLS12_381KeyImporter{})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to add BLS12-381 key importer")
	}
	err = csp.AddWrapper(reflect.TypeOf(&blsKey{}), &BLS12_381Signer{})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to add BLS12-381 signer")
	}
	err = csp.AddWrapper(reflect.TypeOf(&blsKey{}), &BLS12_381Verifier{})
	if err != nil {
		return nil, errors.Wrap(err, "Failed to add BLS12-381 verifier")
	}

	// Add existing wrappers (e.g., ECDSA, RSA) here if needed
	// Example:
	// csp.AddWrapper(reflect.TypeOf(&bccsp.ECDSAKeyGenOpts{}), &ECDSAKeyGenerator{})
	// ...

	return csp, nil
}

// KeyGen generates a key using opts.
func (csp *CSP) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	keyGenerator, found := csp.KeyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyGenOpts' provided [%v]", opts)
	}

	k, err = keyGenerator.KeyGen(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed generating key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}

	return k, nil
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *CSP) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	keyDeriver, found := csp.KeyDerivers[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'Key' provided [%v]", k)
	}

	k, err = keyDeriver.KeyDeriv(k, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed deriving key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}

	return k, nil
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (csp *CSP) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	keyImporter, found := csp.KeyImporters[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyImportOpts' provided [%v]", opts)
	}

	k, err = keyImporter.KeyImport(raw, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed importing key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = csp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing imported key with opts [%v]", opts)
		}
	}

	return k, nil
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (csp *CSP) GetKey(ski []byte) (k bccsp.Key, err error) {
	k, err = csp.ks.GetKey(ski)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting key for SKI [%v]", ski)
	}

	return k, nil
}

// Hash hashes messages msg using options opts.
func (csp *CSP) Hash(msg []byte, opts bccsp.HashOpts) (digest []byte, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'HashOpt' provided [%v]", opts)
	}

	digest, err = hasher.Hash(msg, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed hashing with opts [%v]", opts)
	}

	return digest, nil
}

// GetHash returns an instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (csp *CSP) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	hasher, found := csp.Hashers[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'HashOpt' provided [%v]", opts)
	}

	h, err = hasher.GetHash(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting hash function with opts [%v]", opts)
	}

	return h, nil
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (csp *CSP) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	keyType := reflect.TypeOf(k)
	signer, found := csp.Signers[keyType]
	if !found {
		return nil, errors.Errorf("Unsupported 'SignKey' provided [%s]", keyType)
	}

	signature, err = signer.Sign(k, digest, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed signing with opts [%v]", opts)
	}

	return signature, nil
}

// Verify verifies signature against key k and digest
func (csp *CSP) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty.")
	}

	verifier, found := csp.Verifiers[reflect.TypeOf(k)]
	if !found {
		return false, errors.Errorf("Unsupported 'VerifyKey' provided [%v]", k)
	}

	valid, err = verifier.Verify(k, signature, digest, opts)
	if err != nil {
		return false, errors.Wrapf(err, "Failed verifying with opts [%v]", opts)
	}

	return valid, nil
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *CSP) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	encryptor, found := csp.Encryptors[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'EncryptKey' provided [%v]", k)
	}

	return encryptor.Encrypt(k, plaintext, opts)
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (csp *CSP) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) (plaintext []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	decryptor, found := csp.Decryptors[reflect.TypeOf(k)]
	if !found {
		return nil, errors.Errorf("Unsupported 'DecryptKey' provided [%v]", k)
	}

	plaintext, err = decryptor.Decrypt(k, ciphertext, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed decrypting with opts [%v]", opts)
	}

	return plaintext, nil
}

// AddWrapper binds the passed type to the passed wrapper.
// Notice that that wrapper must be an instance of one of the following interfaces:
// KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher.
func (csp *CSP) AddWrapper(t reflect.Type, w interface{}) error {
	if t == nil {
		return errors.Errorf("type cannot be nil")
	}
	if w == nil {
		return errors.Errorf("wrapper cannot be nil")
	}
	switch dt := w.(type) {
	case KeyGenerator:
		csp.KeyGenerators[t] = dt
	case KeyImporter:
		csp.KeyImporters[t] = dt
	case KeyDeriver:
		csp.KeyDerivers[t] = dt
	case Encryptor:
		csp.Encryptors[t] = dt
	case Decryptor:
		csp.Decryptors[t] = dt
	case Signer:
		csp.Signers[t] = dt
	case Verifier:
		csp.Verifiers[t] = dt
	case Hasher:
		csp.Hashers[t] = dt
	default:
		return errors.Errorf("wrapper type not valid, must be one of: KeyGenerator, KeyDeriver, KeyImporter, Encryptor, Decryptor, Signer, Verifier, Hasher")
	}
	return nil
}
