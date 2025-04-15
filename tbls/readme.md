tbls是门限BLS (Boneh-Lynn-Shacham) ，这里采用Shamir secret sharing 和 polynomial commitments来实现门限签名。
大致思想：对于一个公私钥对<SK, PK>，令SK为需要被共享的秘密，将SK分成n个份额，每个份额叫ski，每个ski可以生成对于的公钥pki。
至少t个ski进行签名，并将这些子签名收集起来可以恢复一个完整签名sig，这个签名相当于SK生成的。SK在秘密共享时会被生成出来，之后的每次签名
（子私钥生成子签名并恢复出一个完整签名）不需要再次生成SK。


下面给出几个术语以及函数的解释，

secret key SK:一个私钥SK，此处被称为秘密，需要被进行秘密共享的私钥，简称秘密私钥SK

shared public key PK(或叫做X):一个公钥PK，是秘密私钥SK对应的公钥

secret key share ski:一个秘密私钥份额ski，秘密私钥SK被切分为多个份额，这个ski是其中的一个份额，简子私钥ski

public key share pki:一个秘密私钥份额ski对应的公钥pki，简称子公钥pki

a threshold BLS signature Si:用一个秘密私钥份额ski对消息msg生成的一个签名Si，简称子签名Si

The full signature S:从超过门限t个的子签名Si中，恢复一个完整的签名S，这个签名相当于秘密私钥SK产生的签名，验签时用秘密私钥SK对应的公钥PK来验签

完整的流程参照tbls_test中的测试用例func TestTBLS(test *testing.T) 即可


