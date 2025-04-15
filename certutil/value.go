package certutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/LatticeBCLab/crypto"
	"github.com/LatticeBCLab/crypto/x509"
	"math/big"
	"time"
)

type CertType string

const (
	InitConsensus CertType = "ConsensusInit" // 初始的共识节点证书
	InitClient    CertType = "ClientInit"    // 初始的客户端证书
	Consensus     CertType = "Consensus"     // 共识节点证书
	Client        CertType = "Client"        // 客户端证书
	RevokeCert    CertType = "RevokeCert"    // 撤销证书
	RevokeClient  CertType = "RevokeClient"  // 撤销客户端证书
)

var (
	CertTypeMap = map[CertType]uint8{
		InitConsensus: 1,
		InitClient:    2,
		Consensus:     3,
		Client:        4,
		RevokeCert:    5,
	}
)

const (
	CertDBlockNumIndex = 0
	CertTypeIndex      = 1
	CertAddressIndex   = 2
)

var (
	CertInfoLength = 3
)

var (
	MAX_SERIAL_NUMBER = new(big.Int).Lsh(big.NewInt(1), 128)
)

var (
	PubTemplate *ecdsa.PublicKey
)

func (c CertType) Uint8() uint8 {
	if u, ok := CertTypeMap[c]; ok {
		return u
	}
	return 0
}
func (c CertType) String() string {
	return string(c)
}
func FromUint(u uint8) (CertType, error) {
	for k, v := range CertTypeMap {
		if v == u {
			return k, nil
		}
	}
	return Client, CertInvalid
}

const (
	EachSigLength = 97
)

// 校验证书的时效行
func VerifyCertTimely(cert *x509.Certificate) error {
	return nil
	//now := time.Now()
	//if now.Before(cert.NotBefore) {
	//	return CertNotYetValid
	//}
	//if now.After(cert.NotAfter) {
	//	return CertExpired
	//}
	//return nil
}

func VerifyNonce(certificate *x509.Certificate, nonce, nonceSign []byte) error {
	s := nonceSign                                      // 密文
	m := nonce                                          // 明文
	key, ok := certificate.PublicKey.(*ecdsa.PublicKey) // 公钥
	if !ok {
		return CertInvalid
	}
	pass := crypto.Instance.VerifySignature(crypto.Instance.CompressPubKey(key), m, s)
	if !pass {
		return CertNotMatch
	}
	return nil
}

type SerialNumberInfo struct {
	LatcId *big.Int
	Index  *big.Int
}

func ParseSerialNumber(info SerialNumberInfo) *big.Int {
	// 生成证书序列号
	orgBig := info.LatcId
	// 证书的机构名在证书序列号的最高位占4个字节, 证书序列号在其余位数
	certNumberLen := info.Index.BitLen()
	header := big.NewInt(0).Lsh(orgBig, uint(certNumberLen))
	return header.Add(header, info.Index)
}

type CertConstructParam struct {
	SerialNumber      *big.Int
	ChainId, DBNumber *big.Int
	OrgName, Address  string
	CertType          CertType
	IsGM              bool
	Start             time.Time
	PubKey            *ecdsa.PublicKey
}

func ConstructionCertificate(serialNumber *big.Int, chainId, dbNumber *big.Int, orgName, address string, certType CertType, isGM bool, start time.Time, pubKey *ecdsa.PublicKey) ([]byte, error) {
	if serialNumber == nil {
		serialNumber, _ = rand.Int(rand.Reader, MAX_SERIAL_NUMBER) //返回在 [0, max) 区间均匀随机分布的一个随机值
	}
	var signAlgo x509.SignatureAlgorithm
	//var priKey
	if isGM {
		signAlgo = x509.SM2WithSM3
	} else {
		signAlgo = x509.ECDSAWithSHA256
	}
	template := x509.Certificate{
		Version:      3,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: chainId.String(),
			Organization: []string{
				orgName,
			},
			Locality: []string{
				CertDBlockNumIndex: dbNumber.String(),
				CertAddressIndex:   address,
				CertTypeIndex:      certType.String(),
			},
		},
		NotBefore:          start,
		NotAfter:           start.Add(100 * 365 * 24 * time.Hour),
		SignatureAlgorithm: signAlgo,
	}
	return x509.GetTbsCertificateDigestEcdsa(&template, pubKey)
}

func MarshalCert(cert *x509.Certificate) []byte {
	return cert.Raw
}
func UnmarshalCert(data []byte) (*x509.Certificate, error) {
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func MarshalCert2Pem(cert *x509.Certificate) ([]byte, error) {
	var certByte []byte
	certBuffer := bytes.NewBuffer(certByte)
	err := pem.Encode(certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return nil, err
	}
	return certBuffer.Bytes(), nil
}
func UnmarshalCertFromPem(data []byte) (*x509.Certificate, error) {
	serverCertBlock, _ := pem.Decode(data)
	if serverCertBlock == nil || serverCertBlock.Type != "CERTIFICATE" {
		return nil, CertInvalid
	}
	serverCert, err := x509.ParseCertificate(serverCertBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return serverCert, nil
}
