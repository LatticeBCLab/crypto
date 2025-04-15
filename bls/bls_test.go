package bls

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
)

/*
bls签名完整流程的测试，
*/
func TestBLS(t *testing.T) {
	//签名内容
	msg := []byte("Hello Boneh-Lynn-Shacham")
	//生成公私钥
	suite := bn256.NewSuite()
	private, public := NewKeyPair(suite, random.New())
	//生成签名
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	//验签
	err = Verify(suite, public, msg, sig)
	//输出签名
	fmt.Println("bls signature:")
	sig_encoded := hex.EncodeToString(sig)
	fmt.Println(sig_encoded)

	require.Nil(t, err)
}

/*
“错误签名”验签
“错误签名”指将原来签名随意改变一下
*/
func TestBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := NewKeyPair(suite, random.New())
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	//修改签名
	sig[0] ^= 0x01
	if Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

/*
"错误密钥"测试
错误密钥，即不是生成签名的密钥，是其他密钥
*/
func TestBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	//生成私钥1
	suite := bn256.NewSuite()
	private, _ := NewKeyPair(suite, random.New())
	//用私钥1生成签名
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	//生成一个公钥2
	_, public := NewKeyPair(suite, random.New())
	//用不匹配的公钥验证签名
	if Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

/*
聚合签名验签
*/
func TestBLSAggregateSignatures(t *testing.T) {
	//签名内容
	msg := []byte("Hello Boneh-Lynn-Shacham")
	//生成两个公私钥对
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	//生成签名1
	sig1, err := Sign(suite, private1, msg)
	require.Nil(t, err)
	//生成签名2
	sig2, err := Sign(suite, private2, msg)
	require.Nil(t, err)
	//聚合签名1和签名2，生成聚合签名
	aggregatedSig, err := AggregateSignatures(suite, sig1, sig2)
	require.Nil(t, err)
	//聚合公钥1和公钥2，生成聚合签名
	aggregatedKey := AggregatePublicKeys(suite, public1, public2)
	//用聚合公钥 验证 聚合签名
	err = Verify(suite, aggregatedKey, msg, aggregatedSig)
	require.Nil(t, err)
}

/*
“错误的聚合签名”验证
错误的聚合签名,即对聚合生成的聚合签名进行修改
*/
func TestBLSFailAggregatedSig(t *testing.T) {
	//签名对象
	msg := []byte("Hello Boneh-Lynn-Shacham")
	//生成签名公私钥对1和2
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	//生成签名1
	sig1, err := Sign(suite, private1, msg)
	require.Nil(t, err)
	//生成签名2
	sig2, err := Sign(suite, private2, msg)
	require.Nil(t, err)
	//聚合签名1和签名2,生成聚合签名
	aggregatedSig, err := AggregateSignatures(suite, sig1, sig2)
	require.Nil(t, err)
	//聚合公钥1和公钥2,生成聚合公钥
	aggregatedKey := AggregatePublicKeys(suite, public1, public2)
	//修改聚合签名,
	aggregatedSig[0] ^= 0x01
	//聚合签名验证
	if Verify(suite, aggregatedKey, msg, aggregatedSig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

/*
"错误的聚合密钥"验证
错误的聚合密钥,即与聚合签名不匹配的聚合密钥，
*/
func TestBLSFailAggregatedKey(t *testing.T) {
	//签名内容
	msg := []byte("Hello Boneh-Lynn-Shacham")
	//生成签名公私钥对1和2
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	//生成公钥3
	_, public3 := NewKeyPair(suite, random.New())
	//生成签名1
	sig1, err := Sign(suite, private1, msg)
	require.Nil(t, err)
	//生成签名2
	sig2, err := Sign(suite, private2, msg)
	require.Nil(t, err)
	//用签名1和签名2生成聚合签名
	aggregatedSig, err := AggregateSignatures(suite, sig1, sig2)
	require.Nil(t, err)
	//用公钥1和公钥2和公钥3聚合生成聚合公钥
	badAggregatedKey := AggregatePublicKeys(suite, public1, public2, public3)
	//用不匹配的聚合公钥  对聚合签名进行验证
	if Verify(suite, badAggregatedKey, msg, aggregatedSig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

/*
批量验证
*/
func TestBLSBatchVerify(t *testing.T) {
	//签名内容1和内容2
	msg1 := []byte("Hello Boneh-Lynn-Shacham")
	msg2 := []byte("Hello Dedis & Boneh-Lynn-Shacham")
	//公私钥对1和2
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	//签名1
	sig1, err := Sign(suite, private1, msg1)
	require.Nil(t, err)
	//签名2
	sig2, err := Sign(suite, private2, msg2)
	require.Nil(t, err)
	//聚合签名
	aggregatedSig, err := AggregateSignatures(suite, sig1, sig2)
	require.Nil(t, err)
	//批量验证
	err = BatchVerify(suite, []kyber.Point{public1, public2}, [][]byte{msg1, msg2}, aggregatedSig)
	require.Nil(t, err)
}

/*
"错误的批量“验证
在进行批量验证前，修改一个签名内容的的值
*/
func TestBLSFailBatchVerify(t *testing.T) {
	//签名内容1和2
	msg1 := []byte("Hello Boneh-Lynn-Shacham")
	msg2 := []byte("Hello Dedis & Boneh-Lynn-Shacham")
	//公私钥对1和2
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	//签名1
	sig1, err := Sign(suite, private1, msg1)
	require.Nil(t, err)
	//签名2
	sig2, err := Sign(suite, private2, msg2)
	require.Nil(t, err)

	t.Run("fails with a bad signature", func(t *testing.T) {
		//生成聚合签名
		aggregatedSig, err := AggregateSignatures(suite, sig1, sig2)
		require.Nil(t, err)
		//修改签名内容2的内容
		msg2[0] ^= 0x01
		//批量验证
		if BatchVerify(suite, []kyber.Point{public1, public2}, [][]byte{msg1, msg2}, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})

	t.Run("fails with a duplicate msg", func(t *testing.T) {
		private3, public3 := NewKeyPair(suite, random.New())
		sig3, err := Sign(suite, private3, msg1)
		require.Nil(t, err)
		aggregatedSig, err := AggregateSignatures(suite, sig1, sig2, sig3)
		require.Nil(t, err)

		if BatchVerify(suite, []kyber.Point{public1, public2, public3}, [][]byte{msg1, msg2, msg1}, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})

}

/*
基准BLS密钥创建，测试密钥生成时间
*/
func BenchmarkBLSKeyCreation(b *testing.B) {
	suite := bn256.NewSuite()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewKeyPair(suite, random.New())
	}
}

/*
基准BLS签名创建，测试签名生成时间
*/
func BenchmarkBLSSign(b *testing.B) {
	suite := bn256.NewSuite()
	private, _ := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(suite, private, msg)
	}
}

/*
基准聚合BLS签名创建，测试聚合签名生成时间
*/
func BenchmarkBLSAggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	private1, _ := NewKeyPair(suite, random.New())
	private2, _ := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignatures(suite, sig1, sig2)
	}
}

/*
基准聚合BLS签名验证，测试聚合签名验证时间
*/
func BenchmarkBLSVerifyAggregate(b *testing.B) {
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)
	sig, err := AggregateSignatures(suite, sig1, sig2)
	key := AggregatePublicKeys(suite, public1, public2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(suite, key, msg, sig)
	}
}

/*
基准BLS签名批量验证，测试签名批量验证的时间
*/
func BenchmarkBLSVerifyBatchVerify(b *testing.B) {
	suite := bn256.NewSuite()

	numSigs := 100
	privates := make([]kyber.Scalar, numSigs)
	publics := make([]kyber.Point, numSigs)
	msgs := make([][]byte, numSigs)
	sigs := make([][]byte, numSigs)
	for i := 0; i < numSigs; i++ {
		private, public := NewKeyPair(suite, random.New())
		privates[i] = private
		publics[i] = public
		msg := make([]byte, 64, 64)
		rand.Read(msg)
		msgs[i] = msg
		sig, err := Sign(suite, private, msg)
		require.Nil(b, err)
		sigs[i] = sig
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggregateSig, _ := AggregateSignatures(suite, sigs...)
		BatchVerify(suite, publics, msgs, aggregateSig)
	}
}

func TestBinaryMarshalAfterAggregation_issue400(t *testing.T) {
	suite := bn256.NewSuite()

	_, public1 := NewKeyPair(suite, random.New())
	_, public2 := NewKeyPair(suite, random.New())

	workingKey := AggregatePublicKeys(suite, public1, public2, public1)

	workingBits, err := workingKey.MarshalBinary()
	require.Nil(t, err)

	workingPoint := suite.G2().Point()
	err = workingPoint.UnmarshalBinary(workingBits)
	require.Nil(t, err)

	// this was failing before the fix
	aggregatedKey := AggregatePublicKeys(suite, public1, public1, public2)

	bits, err := aggregatedKey.MarshalBinary()
	require.Nil(t, err)

	point := suite.G2().Point()
	err = point.UnmarshalBinary(bits)
	require.Nil(t, err)
}
