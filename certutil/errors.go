package certutil

import "gitlab.zlattice.top/zlattice/common/zerror"

var (
	CertExpired,
	CertNotYetValid,
	CertRevoked,
	CertInvalid,
	CertUnknown,
	CertNotAuthorized,
	CertHeightUnknown,
	ClientNotAuthorized,
	SigInvalid,
	SigInlegal,
	SigNotEnough,
	CertNotMatch,
	CertNotScope,
	CertTypeInvalid,
	CertNonEnable error
)

func init() {
	CertExpired = zerror.New("证书已过期", "cert expired", "crypto", 4010)
	CertNotYetValid = zerror.New("证书尚未生效", "cert not yet valid", "crypto", 4011)
	CertRevoked = zerror.New("证书已被吊销", "cert revoked", "crypto", 4012)
	CertInvalid = zerror.New("证书无效", "cert invalid", "crypto", 4013)
	CertUnknown = zerror.New("未知证书", "cert unknown", "crypto", 4014)
	CertNotAuthorized = zerror.New("证书未授权", "cert not authorized", "crypto", 4015)
	CertHeightUnknown = zerror.New("未知证书高度", "cert height unknown", "crypto", 4016)
	ClientNotAuthorized = zerror.New("客户端未授权", "client not authorized", "crypto", 4017)
	SigInvalid = zerror.New("签名无效", "signature invalid", "crypto", 4018)
	SigInlegal = zerror.New("非法签名 %s ", "signature inlegal %s.", "crypto", 4019)
	SigNotEnough = zerror.New("签名不足", "signature not enough", "crypto", 4020)
	CertNotMatch = zerror.New("证书不匹配", "cert not match", "crypto", 4021)
	CertNotScope = zerror.New("证书不在范围内, chainId 不匹配", "The certificate is out of range and the chainId does not match", "crypto", 4022)
	CertTypeInvalid = zerror.New("证书类型不合法", "The certificate type is invalid", "crypto", 4023)
	CertNonEnable = zerror.New("节点证书未启用", "The node certificate is disabled", "crypto", 4024)
}
