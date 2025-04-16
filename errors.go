package crypto

import "gitlab.zlattice.top/zlattice/common/zerror"

var (
	ErrInvalidSig,
	ErrInvalidPubKey,
	errInvalidPubKey,
	errInvalidPrivateKeyLength,
	errInvalidHexPrivateKey,
	errInvalidAESKeyLen error
)

func init() {
	ErrInvalidSig = zerror.New("签名有误，请检查v,r,s字段（sign字段）", "invalid transaction v, r, s values", "crypto", 4000)
	ErrInvalidPubKey = zerror.New("公钥格式有误", "invalid public key crypto", "crypto", 4001)
	errInvalidPubKey = zerror.New("公钥格式有误", "invalid secp256k1 public key", "crypto", 4002)
	errInvalidPrivateKeyLength = zerror.New("私钥长度有误，私钥长度应为 %d bit位", "invalid length, need %d bits", "crypto", 4003)
	errInvalidHexPrivateKey = zerror.New("私钥的编码无法用hex编码解析：%s", "invalid hex string：%s", "crypto", 4004)
	errInvalidAESKeyLen = zerror.New("key长度必须为16，长度有误", "invalid aes key length", "crypto", 4005)

}
