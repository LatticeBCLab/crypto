package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"hash"
	"io"
	"math/big"

	"github.com/LatticeBCLab/crypto/secp256k1"
	"gitlab.zlattice.top/zlattice/common"

	"golang.org/x/crypto/sha3"
)

var (
	IsGM                       = false
	Instance    CryptoInstance = &InternationalCrypto{} //默认非国密
	GM_SIG_LEN                 = 97
	INT_SIG_LEN                = 65
)

func InitGM(GM bool) {
	IsGM = GM
	if IsGM {
		Instance = &GMCrypto{}
	} else {
		Instance = &InternationalCrypto{}
	}
}

type PrivateKey struct {
}

type CryptoInstance interface {
	//生成地址
	CreateContractAddress(b common.Address, nonce uint64) common.Address                    //获取合约地址
	CreateContractAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address //第二种获取合约地址的方法

	//hash
	HashSumByte(data ...[]byte) []byte          //获取Hash的byte格式
	HashSum(data ...[]byte) (h common.Hash)     //获取Hash
	EmptyHash() (h common.Hash)                 //获取空的hash
	EncodeHash(func(io.Writer)) (h common.Hash) //提供方法计算hash

	//生成私钥
	SavePrivateKey(file string, key *ecdsa.PrivateKey) error //直接存储私钥
	GenerateKey() (*ecdsa.PrivateKey, error)                 //生成私钥
	LoadPrivateKey(file string) (*ecdsa.PrivateKey, error)

	//签名类
	HexToECDSA(hexKey string) (*ecdsa.PrivateKey, error)
	ToECDSAUnsafe(d []byte) *ecdsa.PrivateKey
	FromECDSA(pub *ecdsa.PrivateKey) []byte
	UnmarshalPubKey(pub []byte) (*ecdsa.PublicKey, error)
	FromECDSAPub(pub *ecdsa.PublicKey) []byte
	PubKeyToAddress(p ecdsa.PublicKey) common.Address
	EcRecover(hash, sig []byte) ([]byte, error)
	SigToPub(hash, sig []byte) (*ecdsa.PublicKey, error)
	Sign(hash []byte, prv *ecdsa.PrivateKey) (sig []byte, err error) //签名
	//VerifySign(pubKey *ecdsa.PublicKey, hash []byte, signature []byte) bool //签名验证
	VerifySignature(pubKey, hash, signature []byte) bool //签名验证
	ValidateSignatureValues(v byte, r, s *big.Int) bool
	ExtraSeal() int

	//公钥转化
	DecompressPubKey(pubKey []byte) (*ecdsa.PublicKey, error)
	CompressPubKey(pubKey *ecdsa.PublicKey) []byte

	Curve() elliptic.Curve

	Encrypt(plaintext []byte, pub *ecdsa.PublicKey) ([]byte, error)
	// Decrypt sm2 使用的是 C1C2C3 标准
	Decrypt(ciphertext []byte, prv *ecdsa.PrivateKey) ([]byte, error)
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func ZeroPrivateKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func Sha256(data []byte) common.Hash {
	hash := common.Hash{}
	sha := sha256.New()
	sha.Write(data)
	sha.Sum(hash[:0])
	return hash
}

func RecoverCA(sigHash common.Hash, signature []byte) (common.Address, error) {
	inc := InternationalCrypto{}
	pub, err := inc.EcRecover(sigHash[:], signature)
	if err != nil {
		return common.EmptyAddress, err
	}
	if len(pub) == 0 || pub[0] != 4 {
		return common.EmptyAddress, ErrInvalidPubKey
	}
	var addr common.Address
	hash := common.Hash{}
	sha := sha256.New()
	sha.Write(pub[1:])
	sha.Sum(hash[:0])
	copy(addr[:], hash[12:])
	return addr, nil
}

// KeccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// NewKeccakState creates a new KeccakState
func NewKeccakState() KeccakState {
	return sha3.NewLegacyKeccak256().(KeccakState)
}

// Keccak256 calculates and returns the Keccak256 hash of the input data.
func Keccak256(data ...[]byte) []byte {
	b := make([]byte, 32)
	d := NewKeccakState()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(b)
	return b
}
func Keccak256Hash(data ...[]byte) (h common.Hash) {
	d := NewKeccakState()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(h[:])
	return h
}

func ValidateSignatureValues(v byte, r, s *big.Int) bool {
	if r.Cmp(Big1) < 0 || s.Cmp(Big1) < 0 {
		return false
	}
	if s.Cmp(secp256k1halfN) > 0 {
		return false
	}
	return r.Cmp(secp256k1N) < 0 && s.Cmp(secp256k1N) < 0 && (v == 0 || v == 1)
}

func EcRecover(hash, sig []byte) ([]byte, error) {
	if len(sig) == GM_SIG_LEN {
		sig = sig[:INT_SIG_LEN]
	}
	return secp256k1.RecoverPubkey(hash, sig)
}
