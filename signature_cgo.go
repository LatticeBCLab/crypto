package crypto

import (
	"crypto/rand"
	"fmt"

	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/LatticeBCLab/crypto/secp256k1"
	"gitlab.zlattice.top/zlattice/common/math"
)

func (i *InternationalCrypto) EcRecover(hash, sig []byte) ([]byte, error) {
	if len(sig) == GM_SIG_LEN {
		sig = sig[:INT_SIG_LEN]
	}
	return secp256k1.RecoverPubkey(hash, sig)
}

func (i *InternationalCrypto) SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	s, err := i.EcRecover(hash, sig)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(i.Curve(), s)
	return &ecdsa.PublicKey{Curve: i.Curve(), X: x, Y: y}, nil
}

func (i *InternationalCrypto) Sign(hash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}
	secKey := math.PaddedBigBytes(prv.D, prv.Params().BitSize/8)
	defer zeroBytes(secKey)
	return secp256k1.Sign(hash, secKey)
}

func (i *InternationalCrypto) VerifySignature(pubKey, hash, signature []byte) bool {
	return secp256k1.VerifySignature(pubKey, hash, signature)
}

func (i *InternationalCrypto) Curve() elliptic.Curve {
	return secp256k1.S256()
}

func (i *InternationalCrypto) DecompressPubKey(pubKey []byte) (*ecdsa.PublicKey, error) {
	x, y := secp256k1.DecompressPubkey(pubKey)
	if x == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	return &ecdsa.PublicKey{X: x, Y: y, Curve: i.Curve()}, nil
}

func (i *InternationalCrypto) CompressPubKey(pubKey *ecdsa.PublicKey) []byte {
	return secp256k1.CompressPubkey(pubKey.X, pubKey.Y)
}

func (i *InternationalCrypto) Decrypt(ciphertext []byte, prv *ecdsa.PrivateKey) ([]byte, error) {
	return secp256k1.ImportECDSA(prv).Decrypt(ciphertext, nil, nil)
}

func (i *InternationalCrypto) Encrypt(plaintext []byte, pub *ecdsa.PublicKey) ([]byte, error) {
	return secp256k1.Encrypt(rand.Reader, secp256k1.ImportECDSAPublic(pub), plaintext, nil, nil)
}
