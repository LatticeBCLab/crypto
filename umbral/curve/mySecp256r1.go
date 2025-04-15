package curve

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
)

func KeyGen(isGM bool) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	//根据传入参数选择国密/国际曲线
	InitCurve(isGM)
	privateKey, err := ecdsa.GenerateKey(GlobalCurve.Curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return &privateKey.PublicKey, privateKey, nil
}

// ECDSASign 对给定的消息哈希进行签名，压缩签名后返回十六进制字符串
func ECDSASign(privateKeyStr string, messageHash string) (string, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyStr)
	if err != nil {
		return "", err
	}
	privateKey, err := x509.ParseECPrivateKey(privateKeyBytes)
	if err != nil {
		return "", err
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, []byte(messageHash))
	if err != nil {
		return "", err
	}
	rStr, err := r.MarshalText()
	if err != nil {
		return "", err
	}
	sStr, err := s.MarshalText()
	if err != nil {
		return "", err
	}
	var result bytes.Buffer
	w := gzip.NewWriter(&result)
	defer w.Close()
	_, err = w.Write([]byte(string(rStr) + "+" + string(sStr)))
	if err != nil {
		return "", err
	}
	w.Flush()
	return hex.EncodeToString(result.Bytes()), nil
}

func ECDSAVerify(messageHash, signature string, publicKey string) (bool, error) {
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return false, err
	}
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return false, err
	}
	sigBytes, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}
	reader, err := gzip.NewReader(bytes.NewBuffer(sigBytes))
	if err != nil {
		return false, err
	}
	defer reader.Close()
	buf := make([]byte, 1024)
	count, err := reader.Read(buf)
	if err != nil {
		return false, err
	}
	rsArr := strings.Split(string(buf[:count]), "+")
	if len(rsArr) != 2 {
		return false, err
	}
	var r, s big.Int
	err = r.UnmarshalText([]byte(rsArr[0]))
	if err != nil {
		return false, err
	}
	err = s.UnmarshalText([]byte(rsArr[1]))
	if err != nil {
		return false, err
	}
	result := ecdsa.Verify(pubKey.(*ecdsa.PublicKey), []byte(messageHash), &r, &s)
	return result, nil
}
