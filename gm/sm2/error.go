package sm2

import "gitlab.zlattice.top/zlattice/common/zerror"

var (
	RecoverSigToPubErr = zerror.New("签名无法生成公钥，请确定签名正确或字段正确", "recover sig to pub failed", "crypto", 4030)
)
