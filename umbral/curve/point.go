package curve

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tjfoc/gmsm/sm2"
)

// CurveConfig 存储全局曲线配置
type CurveConfig struct {
	Curve elliptic.Curve
	P     *big.Int
	N     *big.Int
}

// GlobalCurve 当前使用的曲线配置
var GlobalCurve CurveConfig

func InitCurve(isGM bool) {
	if isGM {
		GlobalCurve.Curve = sm2.P256Sm2()
	} else {
		GlobalCurve.Curve = secp256k1.S256()
	}
	GlobalCurve.P = GlobalCurve.Curve.Params().P
	GlobalCurve.N = GlobalCurve.Curve.Params().N
}

type CurvePoint = ecdsa.PublicKey

func PointScalarAdd(a, b *CurvePoint) *CurvePoint {
	x, y := GlobalCurve.Curve.Add(a.X, a.Y, b.X, b.Y)
	return &CurvePoint{Curve: GlobalCurve.Curve, X: x, Y: y}
}

func PointScalarMul(a *CurvePoint, k *big.Int) *CurvePoint {
	x, y := GlobalCurve.Curve.ScalarMult(a.X, a.Y, k.Bytes())
	return &CurvePoint{Curve: GlobalCurve.Curve, X: x, Y: y}
}

func BigIntMulBase(k *big.Int) *CurvePoint {
	x, y := GlobalCurve.Curve.ScalarBaseMult(k.Bytes())
	return &CurvePoint{Curve: GlobalCurve.Curve, X: x, Y: y}
}

func PointToBytes(point *CurvePoint) (res []byte) {
	var buf bytes.Buffer
	buf.Write(point.X.Bytes())
	buf.Write(point.Y.Bytes())
	res = buf.Bytes()
	return
}
