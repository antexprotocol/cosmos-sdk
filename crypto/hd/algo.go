package hd

import (
	fmt "fmt"
	"strconv"
	"strings"

	"github.com/cosmos/go-bip39"
	blst "github.com/supranational/blst/bindings/go"
	"gitlab.com/yawning/secp256k1-voi/secec"

	"github.com/cosmos/cosmos-sdk/crypto/keys/bls12_381"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	"github.com/cosmos/cosmos-sdk/crypto/types"
)

// PubKeyType defines an algorithm to derive key-pairs which can be used for cryptographic signing.
type PubKeyType string

const (
	// MultiType implies that a pubkey is a multisignature
	MultiType = PubKeyType("multi")
	// Secp256k1Type uses the Bitcoin secp256k1 ECDSA parameters.
	Secp256k1Type = PubKeyType("secp256k1")
	// Ed25519Type represents the Ed25519Type signature system.
	// It is currently not supported for end-user keys (wallets/ledgers).
	Ed25519Type = PubKeyType("ed25519")
	// Bls12_381Type represents the Bls12_381Type signature system.
	// It is currently not supported for end-user keys (wallets/ledgers).
	Bls12_381Type = PubKeyType("bls12_381")
	// Sr25519Type represents the Sr25519Type signature system.
	Sr25519Type = PubKeyType("sr25519")
)

// Secp256k1 uses the Bitcoin secp256k1 ECDSA parameters.
var Secp256k1 = secp256k1Algo{}

// Bls12_381 uses the BLS signature system on the BLS12-381 curve.
var Bls12_381 = bls12_381Algo{}

type (
	DeriveFn   func(mnemonic, bip39Passphrase, hdPath string) ([]byte, error)
	GenerateFn func(bz []byte) types.PrivKey
)

type WalletGenerator interface {
	Derive(mnemonic, bip39Passphrase, hdPath string) ([]byte, error)
	Generate(bz []byte) types.PrivKey
}

type secp256k1Algo struct{}

func (s secp256k1Algo) Name() PubKeyType {
	return Secp256k1Type
}

// Derive derives and returns the secp256k1 private key for the given seed and HD path.
func (s secp256k1Algo) Derive() DeriveFn {
	return func(mnemonic, bip39Passphrase, hdPath string) ([]byte, error) {
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if err != nil {
			return nil, err
		}

		masterPriv, ch := ComputeMastersFromSeed(seed)
		if len(hdPath) == 0 {
			return masterPriv[:], nil
		}
		derivedKey, err := DerivePrivateKeyForPath(masterPriv, ch, hdPath)

		return derivedKey, err
	}
}

// Generate generates a secp256k1 private key from the given bytes.
func (s secp256k1Algo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		bzArr := make([]byte, secp256k1.PrivKeySize)
		copy(bzArr, bz)

		privKeyObj, err := secec.NewPrivateKey(bz)
		if err != nil {
			panic(err)
		}

		return &secp256k1.PrivKey{Key: privKeyObj.Bytes()}
	}
}

type bls12_381Algo struct{}

func (s bls12_381Algo) Name() PubKeyType {
	return Bls12_381Type
}

// Derive derives and returns the bls12_381 private key for the given seed and HD path.
func (s bls12_381Algo) Derive() DeriveFn {
	return func(mnemonic, bip39Passphrase, hdPath string) ([]byte, error) {
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if err != nil {
			return nil, err
		}

		// master SK   (EIP‑2333)
		sk := blst.DeriveMasterEip2333(seed)

		if hdPath == "" {
			return sk.Serialize(), nil
		}

		indices, err := parseBip44Path(hdPath) // support 44'/118'/…
		if err != nil {
			return nil, err
		}
		for _, idx := range indices {
			sk = sk.DeriveChildEip2333(idx) // blst does HKDF internally
		}
		return sk.Serialize(), nil
	}
}

// -----------------------------------------------------------------------------
// "m/44'/118'/0'/0/0" → []uint32{44'…,118'…,0'…,0,0}
// quote (') ⇒ idx | 0x8000_0000
func parseBip44Path(path string) ([]uint32, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	if strings.HasPrefix(path, "m/") {
		path = path[2:]
	}
	comps := strings.Split(path, "/")
	out := make([]uint32, 0, len(comps))

	for _, c := range comps {
		hardened := strings.HasSuffix(c, "'")
		if hardened {
			c = c[:len(c)-1]
		}
		val64, err := strconv.ParseUint(c, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid component %q: %w", c, err)
		}
		idx := uint32(val64)
		if hardened {
			idx |= 0x80000000
		}
		out = append(out, idx)
	}
	return out, nil
}

// Generate generates a bls12_381 private key from the given bytes.
func (s bls12_381Algo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		buf := make([]byte, 32)
		copy(buf, bz)
		sk, err := bls12_381.NewPrivateKeyFromBytes(buf)
		if err != nil {
			panic(fmt.Errorf("bls12_381 key deserialization failed: %w", err))
		}
		return &sk
	}
}
