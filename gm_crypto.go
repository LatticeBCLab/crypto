package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync/atomic"

	"github.com/LatticeBCLab/crypto/gm/sm2"
	"github.com/LatticeBCLab/crypto/gm/sm3"
	"github.com/LatticeBCLab/crypto/rlp"
	"gitlab.zlattice.top/zlattice/common"
	"gitlab.zlattice.top/zlattice/common/hexutil"
	"gitlab.zlattice.top/zlattice/common/math"
)

type GMCrypto struct {
	emptyHashCache atomic.Value
}

// CreateContractAddress creates an address given the bytes and the nonce
func (i *GMCrypto) CreateContractAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(i.HashSumByte(data)[12:])
}

// CreateContractAddress2 creates an  address given the address bytes, initial
// contract code hash and a salt.
func (i *GMCrypto) CreateContractAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(i.HashSumByte([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

func (i *GMCrypto) HashSumByte(data ...[]byte) []byte {
	hash := sm3.New()
	for _, b := range data {
		hash.Write(b)
	}
	return hash.Sum(nil)
}

func (i *GMCrypto) EncodeHash(fun func(io.Writer)) (h common.Hash) {
	hash := sm3.New()
	fun(hash)
	hash.Sum(h[:0])
	return h
}

func (i *GMCrypto) HashSum(data ...[]byte) (h common.Hash) {
	hash := sm3.New()
	for _, b := range data {
		hash.Write(b)
	}
	hash.Sum(h[:0])
	return h
}

func (i *GMCrypto) EmptyHash() (h common.Hash) {
	if hash := i.emptyHashCache.Load(); (hash != nil && hash != common.Hash{}) {
		return hash.(common.Hash)
	}
	v := i.HashSum(nil)
	i.emptyHashCache.Store(v)
	return v
}

func (i *GMCrypto) SavePrivateKey(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(i.FromECDSA(key))
	return os.WriteFile(file, []byte(k), 0600)
}

func (i *GMCrypto) GenerateKey() (*ecdsa.PrivateKey, error) {
	smpri, _, err := sm2.GenerateKey(rand.Reader)
	return sm2.ToEcdsaPrivate(smpri), err
}

func (i *GMCrypto) LoadPrivateKey(file string) (*ecdsa.PrivateKey, error) {
	buf := make([]byte, 64)
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	if _, err := io.ReadFull(fd, buf); err != nil {
		return nil, err
	}

	key, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}
	return i.toECDSA(key, true)
}

// HexToECDSA parses a secp256k1 private key.
func (i *GMCrypto) HexToECDSA(hexKey string) (*ecdsa.PrivateKey, error) {
	b, err := hexutil.Decode(hexKey)
	if err != nil {
		return nil, errInvalidHexPrivateKey
	}
	return i.toECDSA(b, true)
}

func (i *GMCrypto) ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey {
	priv, _ := i.toECDSA(d, false)
	return priv
}

func (i *GMCrypto) toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = sm2.GetSm2P256V1()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, errInvalidPrivateKeyLength
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(secp256k1N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

func (i *GMCrypto) FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

func (i *GMCrypto) UnmarshalPubKey(pub []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(sm2.GetSm2P256V1(), pub)
	if x == nil {
		return nil, errInvalidPubKey
	}
	return &ecdsa.PublicKey{Curve: sm2.GetSm2P256V1(), X: x, Y: y}, nil
}

func (i *GMCrypto) FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(sm2.GetSm2P256V1(), pub.X, pub.Y)
}

func (i *GMCrypto) PubKeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := i.FromECDSAPub(&p)
	return common.BytesToAddress(i.HashSumByte(pubBytes[1:])[12:])
}

func (i *GMCrypto) ValidateSignatureValues(v byte, r, s *big.Int) bool {
	return sm2.ValidateSignatureValues(v, r, s, false)
}

func (i *GMCrypto) EcRecover(hash, sig []byte) ([]byte, error) {
	ee := new(big.Int).SetBytes(sig[65:])
	smpub, err := sm2.SigToPub(hash, sig[:65], nil, ee)
	if err != nil {
		return nil, err
	}
	return i.FromECDSAPub(smpub), nil
}

func (i *GMCrypto) SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error) {
	ee := new(big.Int).SetBytes(sig[65:])
	smpub, err := sm2.SigToPub(hash, sig[:65], nil, ee)
	if err != nil {
		return nil, err
	}
	return smpub, nil
}

func (i *GMCrypto) Sign(hash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash is required to be exactly 32 bytes (%d)", len(hash))
	}
	smsign, e, err := sm2.Sign(sm2.ToSm2privatekey(prv), nil, hash)
	if err != nil {
		return nil, err
	}
	if len(smsign) != 65 {
		return nil, errors.New(fmt.Sprintf("sig length is wrong !!! sig length is %d ", len(smsign)))
	}
	var pad [32]byte
	buf := e.Bytes()
	copy(pad[32-len(buf):], buf)
	smsign = append(smsign, pad[:]...)
	return smsign, nil
}
func (i *GMCrypto) VerifySignature(pubKey, hash, signature []byte) bool {
	if len(pubKey) == 33 {
		smpub, err := i.DecompressPubKey(pubKey)
		if err != nil {
			return false
		}
		return sm2.Verify(sm2.ToSm2Publickey(smpub), nil, hash, signature)
	}
	smpub, err := i.UnmarshalPubKey(pubKey)
	if err != nil {
		return false
	}

	return sm2.Verify(sm2.ToSm2Publickey(smpub), nil, hash, signature)
}

func (i *GMCrypto) Curve() elliptic.Curve {
	return sm2.GetSm2P256V1()
}

// DecompressPubKey parses a public key in the 33-byte compressed format.
func (i *GMCrypto) DecompressPubKey(pubkey []byte) (*ecdsa.PublicKey, error) {
	if len(pubkey) != 33 {
		return nil, errors.New(fmt.Sprintf("DecompressPubKey length is wrong !,lenth is %d", len(pubkey)))
	}
	return sm2.ToECDSAPublickey(sm2.Decompress(pubkey)), nil
}

// CompressPubkey encodes a public key to the 33-byte compressed format.
func (i *GMCrypto) CompressPubKey(pubKey *ecdsa.PublicKey) []byte {
	if pubKey == nil {
		return nil
	}
	//guomi
	return sm2.Compress(sm2.ToSm2Publickey(pubKey))
}

// 32 + 32 + 1 + 32
func (i *GMCrypto) ExtraSeal() int {
	return 97
}

func (i *GMCrypto) Decrypt(ciphertext []byte, prv *ecdsa.PrivateKey) ([]byte, error) {
	return sm2.Decrypt(sm2.ToSm2privatekey(prv), ciphertext, sm2.C1C2C3)
}

func (i *GMCrypto) Encrypt(plaintext []byte, pub *ecdsa.PublicKey) ([]byte, error) {
	return sm2.Encrypt(sm2.ToSm2Publickey(pub), plaintext, sm2.C1C2C3)
}
