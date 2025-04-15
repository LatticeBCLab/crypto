package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	mrand "math/rand"
	"testing"

	"gitlab.zlattice.top/zlattice/common/hexutil"

	"github.com/LatticeBCLab/crypto/gm/sm2"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func TestSign(t *testing.T) {
	InitGM(true)

	priv, pub, err := sm2.GenerateKey(rand.Reader) // 生成密钥对
	fmt.Println(priv)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("%v\n", priv.Curve.IsOnCurve(priv.X, priv.Y)) // 验证是否为sm2的曲线
	pk := priv.PublicKey.GetUnCompressBytes()
	fmt.Printf("pub:%s\n", hex.EncodeToString(pk))

	//msgHash := RlpHash([]byte("123456"))
	//msg := msgHash[0:]
	msg := []byte("123456")
	sign0, e, err := sm2.Sign(priv, nil, msg)
	signStr := hex.EncodeToString(sign0)
	fmt.Printf("sign0:%s\n", signStr)
	fmt.Printf("sign0 length:%v\n", len(signStr))

	var pad [32]byte
	buf := e.Bytes()
	copy(pad[32-len(buf):], buf)
	sign1 := append(sign0, pad[:]...)
	fmt.Printf("sign1:%s\n", hex.EncodeToString(sign1))
	pubKey, err := Instance.EcRecover(msg, sign1)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("pubKey1:%s\n", hex.EncodeToString(pubKey))

	result := sm2.Verify(pub, nil, msg, sign0)
	if !result {
		fmt.Println("verify failed")
		return
	}
	fmt.Printf("Verify:%v\n", result)
}

func TestBig0(t *testing.T) {
	t.Log(big.NewInt(0).Bytes())
	t.Log(big.NewInt(0).Add(big.NewInt(1), big.NewInt(2)).Uint64())
}

func TestKeccak256(t *testing.T) {
	data, err := generateRandomByte(mrand.Intn(100000))
	require.NoError(t, err)
	expected := Keccak256(data)
	actual := OriginKeccak256(data)
	if !ByteSlicesEqual(expected, actual) {
		t.Logf("not equal data is %x", data)
		t.Fatalf("Expected User-Agent %x does not match %x ", expected, actual)
	}
}

func generateRandomByte(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func ByteSlicesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func OriginKeccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}
func TestAccountKey(t *testing.T) {
	fileKey := `0x95cf1971df42b684853b5c1f5442a9c384e90d89223a774906ab0776802e7a81`
	InitGM(true)
	key, err := Instance.HexToECDSA(fileKey)
	require.Nil(t, err)
	fmt.Println(hexutil.Encode(Instance.FromECDSAPub(&key.PublicKey)))
}
