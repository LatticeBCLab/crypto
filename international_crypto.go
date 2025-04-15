package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/LatticeBCLab/crypto/rlp"
	"io"
	"math/big"
	"os"
	"sync/atomic"

	"gitlab.zlattice.top/zlattice/common"
	"gitlab.zlattice.top/zlattice/common/hexutil"
	"gitlab.zlattice.top/zlattice/common/math"
)

var (
	Big1           = big.NewInt(1)
	secp256k1N, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secp256k1halfN = new(big.Int).Div(secp256k1N, big.NewInt(2))
)

// 国际加密算法
type InternationalCrypto struct {
	emptyHashCache atomic.Value
}

// CreateContractAddress creates an address given the bytes and the nonce
func (i *InternationalCrypto) CreateContractAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(i.HashSumByte(data)[12:])
}

// CreateContractAddress2 creates an  address given the address bytes, initial
// contract code hash and a salt.
func (i *InternationalCrypto) CreateContractAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(i.HashSumByte([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

func (i *InternationalCrypto) HashSumByte(data ...[]byte) []byte {
	hash256 := sha256.New()
	for _, b := range data {
		hash256.Write(b)
	}
	return hash256.Sum(nil)
}

func (i *InternationalCrypto) EncodeHash(fun func(io.Writer)) (h common.Hash) {
	hash := sha256.New()
	fun(hash)
	hash.Sum(h[:0])
	return h
}

func (i *InternationalCrypto) HashSum(data ...[]byte) (h common.Hash) {
	hash256 := sha256.New()
	for _, b := range data {
		hash256.Write(b)
	}
	hash256.Sum(h[:0])
	return h
}

func (i *InternationalCrypto) EmptyHash() (h common.Hash) {
	if hash := i.emptyHashCache.Load(); (hash != nil && hash != common.Hash{}) {
		return hash.(common.Hash)
	}
	v := i.HashSum(nil)
	i.emptyHashCache.Store(v)
	return v
}

func (i *InternationalCrypto) SavePrivateKey(file string, key *ecdsa.PrivateKey) error {
	k := hex.EncodeToString(i.FromECDSA(key))
	return os.WriteFile(file, []byte(k), 0600)
}

func (i *InternationalCrypto) GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(i.Curve(), rand.Reader)
}

func (i *InternationalCrypto) LoadPrivateKey(file string) (*ecdsa.PrivateKey, error) {
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
func (i *InternationalCrypto) HexToECDSA(hexKey string) (*ecdsa.PrivateKey, error) {
	b, err := hexutil.Decode(hexKey)
	if err != nil {
		return nil, errInvalidHexPrivateKey
	}
	return i.toECDSA(b, true)
}

func (i *InternationalCrypto) ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey {
	priv, _ := i.toECDSA(d, false)
	return priv
}

func (i *InternationalCrypto) toECDSA(d []byte, strict bool) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = i.Curve()
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

func (i *InternationalCrypto) FromECDSA(priv *ecdsa.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

func (i *InternationalCrypto) UnmarshalPubKey(pub []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(i.Curve(), pub)
	if x == nil {
		return nil, errInvalidPubKey
	}
	return &ecdsa.PublicKey{Curve: i.Curve(), X: x, Y: y}, nil
}

func (i *InternationalCrypto) FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(i.Curve(), pub.X, pub.Y)
}

func (i *InternationalCrypto) PubKeyToAddress(p ecdsa.PublicKey) common.Address {
	pubBytes := i.FromECDSAPub(&p)
	return common.BytesToAddress(i.HashSumByte(pubBytes[1:])[12:])
}

func (i *InternationalCrypto) ValidateSignatureValues(v byte, r, s *big.Int) bool {
	if r.Cmp(Big1) < 0 || s.Cmp(Big1) < 0 {
		return false
	}
	//if s.Cmp(secp256k1halfN) > 0 {
	//	log.Error("s > secp256k1halfN ")
	//	return false
	//}
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}

// 32 + 32 + 1
func (i *InternationalCrypto) ExtraSeal() int {
	return 65
}
