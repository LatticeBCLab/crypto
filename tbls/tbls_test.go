package tbls

import (
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/require"
	"gitlab.zlattice.top/zlattice/common/hexutil"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"testing"
	//"go.dedis.ch/kyber/v3/sign/bls"
)

/*
门限bls的完整测试过程
*/
func TestTBLS(test *testing.T) {
	var err error
	//签名的对象msg
	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	n := 10
	t := n/2 + 1 //门限阈值
	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), t, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)

	for _, x := range priPoly.Shares(n) {
		//生成n个子签名
		sig, err := Sign(suite, x, msg)
		//对子签名进行验证
		err1 := tbls.Verify(suite, pubPoly, msg, sig)
		if err1 != nil {
			fmt.Println("子签名验证错误")
			break
		}

		require.Nil(test, err)
		//将每个子签名保存起来，之后用于聚合生成单个签名
		sigShares = append(sigShares, sig)
	}
	//从n个子签名中恢复(聚合生成)一个签名，即聚合后的单签
	sig, err := Recover(suite, pubPoly, msg, sigShares, t, n)
	require.Nil(test, err)
	//验签
	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)

	fmt.Println("聚合生的的签个签名 sig:")
	sig_encoded := hex.EncodeToString(sig)
	fmt.Println(sig_encoded)

	require.Nil(test, err)
}

type server struct {
	privateKey *share.PriShare
	publicKey  *share.PubPoly
	message    []byte
}

func makeServer(n, f, threshold int, suite *bn256.Suite) ([]server, [][]byte) {
	m := "hello"

	servers := make([]server, n)

	secret := suite.G1().Scalar().Pick(suite.RandomStream())
	priPoly := share.NewPriPoly(suite.G2(), threshold, secret, suite.RandomStream())
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	sigShares := make([][]byte, 0)

	for i, x := range priPoly.Shares(n) {
		servers[i].privateKey = x      //将私钥赋予节点i
		servers[i].publicKey = pubPoly //将公钥赋予节点i
		servers[i].message = []byte(m)
		sig, _ := tbls.Sign(suite, servers[i].privateKey, servers[i].message) //生成部分签名
		sigShares = append(sigShares, sig)                                    //生成数字签名
	}
	return servers, sigShares
}

func threshldVerify(servers []server, n, f, threshold int, suite *bn256.Suite, sigShares [][]byte, t *testing.T) []string {
	results := make([]string, n)
	sig, _ := tbls.Recover(suite, servers[0].publicKey, servers[0].message, sigShares, threshold, n)
	err := bls.Verify(suite, servers[0].publicKey.Commit(), servers[0].message, sig) //用公钥验证数字签名
	if err == nil {
		results[0] = "Success"
	} else {
		results[0] = "Fault"
	}
	return results
}

func TestWithOneFailer(t *testing.T) {
	suite := bn256.NewSuite()
	n := 4
	f := 1
	threshold := 2*f + 1
	servers, sigShares := makeServer(n, f, threshold, suite)
	temp := sigShares[0]
	sigShares[0] = sigShares[1]
	sigShares[1] = temp
	results := threshldVerify(servers, n, f, threshold, suite, sigShares, t)
	//for i := range results {
	if results[0] != "Success" {
		t.Errorf("server [%d] recover fault.\n", 0)
	}
	//}
}
func TestRestoreKey(t *testing.T) {
	suite := bn256.NewSuite()
	priShares := make([]*share.PriShare, 3, 3)

	priShares[0] = &share.PriShare{
		I: 0,
		V: suite.G2().Scalar().Zero(),
	}
	decode, _ := hexutil.Decode("0x38ea2dba8b63d6d5ac8e4da36e2071b14020d9021d7fab8f07027aea90566ab8")
	priShares[0].V.UnmarshalBinary(decode)

	priShares[1] = &share.PriShare{
		I: 1,
		V: suite.G2().Scalar().Zero(),
	}
	decode, _ = hexutil.Decode("0x298deb84eab6b49f80007b72aabf82af543c89ecb2e4e34c4120abddda186801")
	priShares[1].V.UnmarshalBinary(decode)

	priShares[2] = &share.PriShare{
		I: 2,
		V: suite.G2().Scalar().Zero(),
	}
	decode, _ = hexutil.Decode("0x226a72bf59fb33411eb1d10024f600a176ec76bad0f61c3df3b69e221a177bec")
	priShares[2].V.UnmarshalBinary(decode)

	signs := make([][]byte, 0)

	for i := 0; i < 3; i++ {
		sign, _ := tbls.Sign(suite, priShares[i], []byte("hello"))
		signs = append(signs, sign)
	}
	point := make([]kyber.Point, 3, 3)
	point0, _ := hexutil.Decode("0x8c2d0cb68210d01b3589d24279c6c5204f98ace21e0304fd0b91b905fab386462191a2874eaf3fa156212d323f659d85878f6bcd61849dcd7843ae1ad575a4af04801e2a41f10f466227b88095b9f9ff5a8ac2c8b1f94bfaf964043edd44d899738e5aca0469c6002955da5d8fb48894cc27336a4eea3e04041c08b69f509a0c")
	point1, _ := hexutil.Decode("0x2a7d90baa616a11344e8f99330ca167e2eaf24bf68237498abeb62c0e0f70d16681c496d00af9712fb74081cae9f4ef9156327daa16449018b79c1598e72bd8d1a83c04a23c5745cc784c8b99e0189c308f3242d408cc8f5f00053ccafd7bd3166dedc093f2158d9d6ccc560b957322e66f317481b8e8b404a6d2deecdc3118a")
	point2, _ := hexutil.Decode("0x3f7b68cd853d557ed698cacf9c3c137bfb3da66c78a26c9958608a96c2c30af9586b5a225807b455dcb48244ae598e4838711924bc35304ea49a4f16a1c0aa8e0252c596563f9f30bdb1f4268ca89bd9a84ecb2891c97cba00100198374e5fc16fe1d1567cf8ef6f816c3250b40a3d121163dd04b82c6ac4b2af5047b591c809")
	point[0] = suite.G2().Point()
	point[0].UnmarshalBinary(point0)
	point[1] = suite.G2().Point()
	point[1].UnmarshalBinary(point1)
	point[2] = suite.G2().Point()
	point[2].UnmarshalBinary(point2)

	pub := share.NewPubPoly(suite.G2(), suite.G2().Point().Base(), point)

	sig, _ := tbls.Recover(suite, pub, []byte("hello"), signs, 3, 3)
	err := bls.Verify(suite, pub.Commit(), []byte("hello"), sig) //用公钥验证数字签名
	if err == nil {
		fmt.Println("Success")
	} else {
		fmt.Println("Fault")
	}
}
