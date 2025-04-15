package utils

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"hash"
	"io"
	"math/big"
	"os"

	"github.com/LatticeBCLab/crypto/umbral/curve"
	"github.com/LatticeBCLab/crypto/umbral/math"

	"github.com/tjfoc/gmsm/sm3"
	"golang.org/x/crypto/sha3"
)

// concat bytes
func ConcatBytes(a, b []byte) []byte {
	var buf bytes.Buffer
	buf.Write(a)
	buf.Write(b)
	return buf.Bytes()
}

// convert message to hash value,增加国密可选
func Sha3Hash(message []byte, isGM bool) ([]byte, error) {
	//定义通用哈希
	var sha hash.Hash
	//根据情况选择哈希算法
	if isGM {
		sha = sm3.New()
	} else {
		sha = sha3.New256()
	}
	_, err := sha.Write(message)
	if err != nil {
		return nil, err
	}
	return sha.Sum(nil), nil
}

// map hash value to curve
func HashToCurve(hash []byte) *big.Int {
	hashInt := new(big.Int).SetBytes(hash)
	return hashInt.Mod(hashInt, curve.GlobalCurve.N) //替换为全局可设置的国密/国际曲线参数
}

func GetCoefficients(a *big.Int, d *big.Int, t int) ([]*big.Int, error) {
	coefficients := []*big.Int{math.BigIntMul(a, math.GetInvert(d))}
	for i := 1; i < t; i++ {
		f, err := ecdsa.GenerateKey(curve.GlobalCurve.Curve, rand.Reader) //替换为全局可设置的国密/国际曲线参数
		if err != nil {
			return nil, err
		}
		coefficients = append(coefficients, f.D)
	}
	return coefficients, nil
}

func GetPolynomialValue(coefficients []*big.Int, x *big.Int) *big.Int {
	t := len(coefficients)
	result := coefficients[t-1]
	for i := 1; i < t; i++ {
		result = math.BigIntAdd(math.BigIntMul(result, x), coefficients[t-i-1])
	}
	return result
}

// Gzip
func GzipCompress(bs []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(bs)
	zw.Flush()
	zw.Close()

	return buf.Bytes()
}

func GzipUnCompress(bs []byte) ([]byte, error) {
	var buf bytes.Buffer
	bsBuf := bytes.NewBuffer(bs)
	zr, err := gzip.NewReader(bsBuf)
	if err != nil {
		return nil, err
	}
	io.Copy(&buf, zr)
	zr.Close()

	return buf.Bytes(), nil
}

func FileToMd5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
