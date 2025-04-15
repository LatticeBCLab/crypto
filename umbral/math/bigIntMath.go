package math

import (
	"math/big"

	"github.com/LatticeBCLab/crypto/umbral/curve"
)

func BigIntAdd(a, b *big.Int) (res *big.Int) {
	res = new(big.Int).Add(a, b)
	res.Mod(res, curve.GlobalCurve.N) //替换为全局可设置的国密/国际曲线参数
	return
}

func BigIntSub(a, b *big.Int) (res *big.Int) {
	res = new(big.Int)
	res.Sub(a, b)
	res.Mod(res, curve.GlobalCurve.N) //替换为全局可设置的国密/国际曲线参数
	return
}

func BigIntMul(a, b *big.Int) (res *big.Int) {
	res = new(big.Int).Mul(a, b)
	res.Mod(res, curve.GlobalCurve.N) //替换为全局可设置的国密/国际曲线参数
	return
}

func GetInvert(a *big.Int) (res *big.Int) {
	res = new(big.Int).ModInverse(a, curve.GlobalCurve.N) //替换为全局可设置的国密/国际曲线参数
	return
}
