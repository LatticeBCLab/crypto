package linkable_ring_signature

import (
	"crypto/elliptic"
	crand "crypto/rand"
	"fmt"
	"math/big"
	"math/rand"
	"testing"
)

func Test_verify(t *testing.T) {

	rand.Seed(1)
	privKey := make([]Private, 5) //存放私钥
	pubKey := make([]Public, 5)   //存放公钥
	var curve = elliptic.P256()
	var err error
	//生成5个公私钥对
	for i := range privKey {
		privKey[i].D = new(big.Int)
		pubKey[i].y = new(big.Int)
		pubKey[i].x = new(big.Int)
		pubKey[i].Curve = curve
		//		privKey[i].D, err = randFieldElement(curve, rand)
		privKey[i].D.SetInt64((int64(rand.Intn(173113)))) //随机产生私钥
		if err != nil {
			fmt.Println(err.Error())
		}
		pubKey[i].x, pubKey[i].y = curve.ScalarBaseMult(privKey[i].D.Bytes())

	}
	//公钥环
	pubkeyRing := &PublicKeyRing{
		pubKey,
	}
	/*##############################使用环外成员##############################
	var testPriv Private
	testPriv.D = new(big.Int).SetInt64((int64(rand.Intn(173311))))
	spew.Dump(testPriv)
	*/

	m := new(big.Int).SetInt64(193127)
	//生成签名，pubkeyRing是环，即多个公钥，privKey[1]是实际上进行签名的公钥
	rs, err := sign(crand.Reader, pubkeyRing, m.Bytes(), privKey[1], 2)
	//验签
	if verify(rs, pubkeyRing, m.Bytes()) {
		fmt.Println("true")
	} else {
		fmt.Println("false")
	}

}
