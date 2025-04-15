package umbral

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/LatticeBCLab/crypto/umbral/curve"
	"github.com/LatticeBCLab/crypto/umbral/recrypt"
	"github.com/LatticeBCLab/crypto/umbral/utils"
)

type Capsule struct {
	E *ecdsa.PublicKey
	V *ecdsa.PublicKey
	S *big.Int
	C *ecdsa.PublicKey
}

type Cipher_before_re struct {
	CipherText []byte
	Capsule    *Capsule
}

// 每个节点持有一个重加密的密钥碎片kfrag，每个节点执行重加密，得到各自的结果。
func ReEncrypt(KF, cipher []byte, isGM bool) ([]byte, error) {
	//	基于传入的json格式的字符串，组装目标对象
	type FkragJson struct {
		ID string `json:"id"`
		RK string `json:"rk"`
		XA string `json:"x_a"`
		U1 string `json:"u_1"`
		Z1 string `json:"z_1"`
		Z2 string `json:"z_2"`
		C  string `json:"c"`
		T  string `json:"t"`
	}
	var data FkragJson
	err := json.Unmarshal(KF, &data)
	if err != nil {
		return nil, err
	}
	kfrag, err := recrypt.DeserializationKFrag(data.ID, data.RK, data.XA, data.U1, data.Z1, data.Z2, data.C, data.T, isGM)
	if err != nil {
		return nil, err
	}

	type CipherData struct {
		CipherText string `json:"CipherText"`
		Capsule    struct {
			E string `json:"E"`
			V string `json:"V"`
			S string `json:"S"`
			C string `json:"C"`
		} `json:"Capsule"`
	}
	var cipherData CipherData
	err = json.Unmarshal(cipher, &cipherData)
	if err != nil {
		return nil, err
	}
	cipherText, err := hex.DecodeString(cipherData.CipherText)
	if err != nil {
		return nil, err
	}
	e, err := recrypt.DeserializationPublicKey(cipherData.Capsule.E, isGM)
	if err != nil {
		return nil, err
	}
	v, err := recrypt.DeserializationPublicKey(cipherData.Capsule.V, isGM)
	if err != nil {
		return nil, err
	}
	sBytes, err := hex.DecodeString(cipherData.Capsule.S)
	if err != nil {
		return nil, err
	}
	s := new(big.Int).SetBytes(sBytes)
	c, err := recrypt.DeserializationPublicKey(cipherData.Capsule.C, isGM)
	if err != nil {
		return nil, err
	}
	capsule := recrypt.Capsule{
		E: e,
		V: v,
		S: s,
		C: c,
	}
	cipher_before := recrypt.Cipher_before_re{
		CipherText: cipherText,
		Capsule:    &capsule,
	}
	cfrag, err := recrypt.NewReEncrypt(*kfrag, &cipher_before)
	if err != nil {
		return nil, err
	}

	e_1, v_1, id, x_a, t := recrypt.SerializationCFrag(*cfrag)

	cfragTemp := map[string]string{
		"e_1": e_1,
		"v_1": v_1,
		"id":  id,
		"x_a": x_a,
		"t":   t,
	}

	cfragJson, err := json.Marshal(cfragTemp)
	if err != nil {
		return nil, err
	}

	return cfragJson, nil
}

func DeserializationPrivateKey(skHex string) (*ecdsa.PrivateKey, error) {
	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(skBytes)
	x, y := curve.GlobalCurve.Curve.ScalarBaseMult(d.Bytes())

	// 构建公钥结构体
	pk := ecdsa.PublicKey{
		Curve: curve.GlobalCurve.Curve,
		X:     x,
		Y:     y,
	}

	// 输出公钥的X
	sk := ecdsa.PrivateKey{
		PublicKey: pk,
		D:         d,
	}
	return &sk, nil
}

func DeserializationPublicKey(pkHex string) (*ecdsa.PublicKey, error) {
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, err
	}
	// 分别解析X和Y坐标
	x := new(big.Int).SetBytes(pkBytes[:32])
	y := new(big.Int).SetBytes(pkBytes[32:])
	pk := ecdsa.PublicKey{
		Curve: curve.GlobalCurve.Curve,
		X:     x,
		Y:     y,
	}
	return &pk, nil
}

func NewDecrypt(aPriKey *ecdsa.PrivateKey, cipher *Cipher_before_re, condition *big.Int, isGM bool) (plaintext string, err error) {
	keyBytes, err := Decapsulate(aPriKey, cipher.Capsule, condition, isGM) //增加国密可选
	if err != nil {
		return "", err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce

	//按是否选用国密模式做区分,SM4的默认数据分块大小是16字节（128位）
	if isGM {
		plaintext, err = recrypt.Sm4gcmDecrypt(key[:16], string(cipher.CipherText))
	} else {
		plaintext, err = aesgcmDecrypt(key[:32], string(cipher.CipherText))
	}
	if err != nil {
		return "", err
	}
	return plaintext, nil
}

// Recreate aes key
func Decapsulate(aPriKey *ecdsa.PrivateKey, capsule *Capsule, condition *big.Int, isGM bool) (keyBytes []byte, err error) {
	point1 := curve.PointScalarAdd(capsule.E, capsule.V)
	point2 := curve.PointScalarMul(point1, aPriKey.D)
	point := curve.PointScalarMul(point2, condition)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point), isGM)
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func aesgcmDecrypt(secretKey string, ciphertext string) (string, error) {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return "", err
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
