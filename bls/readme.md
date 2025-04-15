
BLS (Boneh-Lynn-Shacham) 签名是一种数字签名算法，它基于椭圆曲线密码学和离散对数问题，具有较高的效率和安全性。BLS 签名的主要优点是在签名和验证时，
它的计算复杂度相对于其他数字签名算法更低，因此可以更快地生成和验证签名，这对于资源受限的设备（如 IoT 设备）和高吞吐量场景非常有用。
bls的使用示例如下所示
```
func TestBLS(t *testing.T) {
    //被签名的消息msg
	msg := []byte("Hello Boneh-Lynn-Shacham")
	
	 //生成私钥private和公钥public
	suite := bn256.NewSuite()
	private, public := NewKeyPair(suite, random.New())
	
	//用私钥private对消息msg进行签名,生成的签名sig
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	
	//验证签名sig是否有效
	err = Verify(suite, public, msg, sig)
	
    //输出签名sig，输出的签名格式是十六进制形式
	fmt.Println("bls signature:")
	sig_encoded := hex.EncodeToString(sig)
	fmt.Println(sig_encoded)

	require.Nil(t, err)
}

 ```