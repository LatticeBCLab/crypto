package recrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/LatticeBCLab/crypto/umbral/curve"
	"github.com/LatticeBCLab/crypto/umbral/math"
	"github.com/LatticeBCLab/crypto/umbral/utils"

	"github.com/tjfoc/gmsm/sm4"
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

type Cipher_after_re struct {
	CF         []CFrag
	CipherText []byte
}

type KFrag struct {
	Id  *ecdsa.PrivateKey
	Rk  *big.Int
	X_A *ecdsa.PublicKey
	U_1 *ecdsa.PublicKey
	z_1 *big.Int
	z_2 *big.Int
	C   *ecdsa.PublicKey
	T   *big.Int
}

type CFrag struct {
	E_1 *ecdsa.PublicKey
	V_1 *ecdsa.PublicKey
	id  *ecdsa.PrivateKey
	X_A *ecdsa.PublicKey
	T   *big.Int
}

func SerializationPublicKey(pk *ecdsa.PublicKey) string {
	pkBytes := utils.ConcatBytes(pk.X.Bytes(), pk.Y.Bytes())
	pkHex := hex.EncodeToString(pkBytes)
	return pkHex
}

func DeserializationPublicKey(pkHex string, isGM bool) (*ecdsa.PublicKey, error) {
	pkBytes, err := hex.DecodeString(pkHex)
	if err != nil {
		return nil, err
	}
	// 分别解析X和Y坐标
	x := new(big.Int).SetBytes(pkBytes[:32])
	y := new(big.Int).SetBytes(pkBytes[32:])
	//根据传入参数选择国密或国际曲线
	curve.InitCurve(isGM)
	pk := ecdsa.PublicKey{
		Curve: curve.GlobalCurve.Curve,
		X:     x,
		Y:     y,
	}
	return &pk, nil
}

func SerializationPrivateKey(sk *ecdsa.PrivateKey) string {
	skHex := hex.EncodeToString(sk.D.Bytes())
	return skHex
}

func DeserializationPrivateKey(skHex string, isGM bool) (*ecdsa.PrivateKey, error) {
	skBytes, err := hex.DecodeString(skHex)
	if err != nil {
		return nil, err
	}
	d := new(big.Int).SetBytes(skBytes)
	//根据传入参数选择国密或国际曲线
	curve.InitCurve(isGM)
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

func SerializationKFrag(kf KFrag) (string, string, string, string, string, string, string, string) {
	id := SerializationPrivateKey(kf.Id)
	rk := hex.EncodeToString(kf.Rk.Bytes())
	x_a := SerializationPublicKey(kf.X_A)
	u_1 := SerializationPublicKey(kf.U_1)
	z_1 := hex.EncodeToString(kf.z_1.Bytes())
	z_2 := hex.EncodeToString(kf.z_2.Bytes())
	c := SerializationPublicKey(kf.C)
	t := hex.EncodeToString(kf.T.Bytes())
	return id, rk, x_a, u_1, z_1, z_2, c, t
}

func DeserializationKFrag(idHex string, rkHex string, x_aHex string, u_1Hex string, z_1Hex string, z_2Hex string, cHex string, tHex string, isGM bool) (*KFrag, error) {
	id, err := DeserializationPrivateKey(idHex, isGM)
	if err != nil {
		return nil, err
	}
	rkBytes, err := hex.DecodeString(rkHex)
	if err != nil {
		return nil, err
	}
	rk := new(big.Int).SetBytes(rkBytes)
	x_a, err := DeserializationPublicKey(x_aHex, isGM)
	if err != nil {
		return nil, err
	}
	u_1, err := DeserializationPublicKey(u_1Hex, isGM)
	if err != nil {
		return nil, err
	}
	z_1Bytes, err := hex.DecodeString(z_1Hex)
	if err != nil {
		return nil, err
	}
	z_1 := new(big.Int).SetBytes(z_1Bytes)
	z_2Bytes, err := hex.DecodeString(z_2Hex)
	if err != nil {
		return nil, err
	}
	z_2 := new(big.Int).SetBytes(z_2Bytes)
	c, err := DeserializationPublicKey(cHex, isGM)
	if err != nil {
		return nil, err
	}
	tBytes, err := hex.DecodeString(tHex)
	if err != nil {
		return nil, err
	}
	t := new(big.Int).SetBytes(tBytes)
	kfrag := KFrag{
		Id:  id,
		Rk:  rk,
		X_A: x_a,
		U_1: u_1,
		z_1: z_1,
		z_2: z_2,
		C:   c,
		T:   t,
	}
	return &kfrag, nil
}

// 序列化CFrag
func SerializationCFrag(cf CFrag) (string, string, string, string, string) {
	e_1 := SerializationPublicKey(cf.E_1)
	v_1 := SerializationPublicKey(cf.V_1)
	id := SerializationPrivateKey(cf.id)
	x_a := SerializationPublicKey(cf.X_A)
	t := hex.EncodeToString(cf.T.Bytes())
	return e_1, v_1, id, x_a, t
}

func DeserializationCFrag(e_1Hex string, v_1Hex string, idHex string, x_aHex string, tHex string, isGM bool) (*CFrag, error) {
	e_1, err := DeserializationPublicKey(e_1Hex, isGM)
	if err != nil {
		return nil, err
	}
	v_1, err := DeserializationPublicKey(v_1Hex, isGM)
	if err != nil {
		return nil, err
	}
	id, err := DeserializationPrivateKey(idHex, isGM)
	if err != nil {
		return nil, err
	}
	x_a, err := DeserializationPublicKey(x_aHex, isGM)
	if err != nil {
		return nil, err
	}
	tBytes, err := hex.DecodeString(tHex)
	if err != nil {
		return nil, err
	}
	t := new(big.Int).SetBytes(tBytes)
	cfrag := CFrag{
		E_1: e_1,
		V_1: v_1,
		id:  id,
		X_A: x_a,
		T:   t,
	}
	return &cfrag, nil
}

func Encapsulate(pubKey *ecdsa.PublicKey, condition *big.Int, isGM bool) (keyBytes []byte, capsule *Capsule, err error) {
	s := new(big.Int)
	// generate E,V key-pairs
	pubE, priE, err := curve.KeyGen(isGM) //增加国密可选项
	if err != nil {
		return nil, nil, err
	}
	pubV, priV, err := curve.KeyGen(isGM) //增加国密可选项
	if err != nil {
		return nil, nil, err
	}
	// get H2(E || V)
	h := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(pubE),
			curve.PointToBytes(pubV)))
	// get s = v + e * H2(E || V)
	s = math.BigIntAdd(priV.D, math.BigIntMul(priE.D, h))
	// get (pk_A)^{e+v}
	point1 := curve.PointScalarMul(pubKey, math.BigIntAdd(priE.D, priV.D))
	point := curve.PointScalarMul(point1, condition)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point), isGM) //增加国密可选
	if err != nil {
		return nil, nil, err
	}
	capsule = &Capsule{
		E: pubE,
		V: pubV,
		S: s,
		C: curve.BigIntMulBase(condition),
	}
	return keyBytes, capsule, nil
}

func Encrypt(pubKey *ecdsa.PublicKey, infileName string, encfileName string, condition *big.Int, isGM bool) (cipher *Cipher_before_re, err error) {
	keyBytes, capsule, err := Encapsulate(pubKey, condition, isGM) //增加国密可选
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	err = OFBFileEncrypt(key[:32], keyBytes[:12], infileName, encfileName)
	if err != nil {
		return nil, err
	}
	cipher = &Cipher_before_re{
		Capsule: capsule,
	}
	return cipher, nil
}

// 输入输出不采用文件，直接返回。
func NewEncrypt(pubKey *ecdsa.PublicKey, plaintext string, condition *big.Int, isGM bool) (cipher *Cipher_before_re, err error) {
	keyBytes, capsule, err := Encapsulate(pubKey, condition, isGM) //增加国密可选
	if err != nil {
		return nil, err
	}
	key := hex.EncodeToString(keyBytes)

	//按是否选用国密模式做区分，SM4的默认数据分块大小是16字节（128位）
	var cipherText []byte
	if isGM {
		cipherText, err = Sm4gcmEncrypt(key[:16], plaintext)
	} else {
		cipherText, err = aesgcmEncrypt(key[:32], plaintext)
	}

	if err != nil {
		return nil, err
	}
	cipher = &Cipher_before_re{
		CipherText: cipherText,
		Capsule:    capsule,
	}
	return cipher, nil
}

func aesgcmEncrypt(secretKey string, plaintext string) ([]byte, error) {
	aes, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return ciphertext, nil
}

// Recreate aes key
func Decapsulate(aPriKey *ecdsa.PrivateKey, capsule *Capsule, condition *big.Int, isGM bool) (keyBytes []byte, err error) {
	point1 := curve.PointScalarAdd(capsule.E, capsule.V)
	point2 := curve.PointScalarMul(point1, aPriKey.D)
	point := curve.PointScalarMul(point2, condition)
	// generate aes key
	keyBytes, err = utils.Sha3Hash(curve.PointToBytes(point), isGM) //增加国密可选
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func Decrypt(aPriKey *ecdsa.PrivateKey, cipher *Cipher_before_re, encfileName string, decfileName string, condition *big.Int, isGM bool) (err error) {
	keyBytes, err := Decapsulate(aPriKey, cipher.Capsule, condition, isGM) //增加国密可选
	if err != nil {
		return err
	}
	key := hex.EncodeToString(keyBytes)
	// use aes gcm algorithm to encrypt
	// mark keyBytes[:12] as nonce
	err = OFBFileDecrypt(key[:32], keyBytes[:12], encfileName, decfileName)
	return err
}

// 输入输出不采用文件，直接返回,支持国际和国密可选
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
		plaintext, err = Sm4gcmDecrypt(key[:16], string(cipher.CipherText))
	} else {
		plaintext, err = aesgcmDecrypt(key[:32], string(cipher.CipherText))
	}
	if err != nil {
		return "", err
	}
	return plaintext, nil
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

func CheckCapsule(capsule *Capsule, condition *big.Int) (err error) {
	left := curve.BigIntMulBase(capsule.S)
	h1 := utils.HashToCurve(
		utils.ConcatBytes(
			curve.PointToBytes(capsule.E),
			curve.PointToBytes(capsule.V)))
	h2 := curve.PointScalarMul(capsule.E, h1)
	right := curve.PointScalarAdd(capsule.V, h2)
	if !left.Equal(right) {
		return fmt.Errorf("%s", "Capsule not match")
	}
	if !capsule.C.Equal(curve.BigIntMulBase(condition)) {
		return fmt.Errorf("%s", "Condition not match")
	}
	return nil
}

func ReKeyGen(aPriKey *ecdsa.PrivateKey, bPubKey *ecdsa.PublicKey, N int, t int, condition *big.Int, isGM bool) ([]KFrag, error) {
	if t < 2 {
		return nil, fmt.Errorf("%s", "t must bigger than 1")
	}
	X_A, x_A, err := curve.KeyGen(isGM) //增加国密可选项
	if err != nil {
		return nil, err
	}
	// get d = H3(X_A,pk_b,pk_b^(x_A))
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(X_A),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(curve.PointScalarMul(bPubKey, x_A.D))))
	coefficients, err := utils.GetCoefficients(aPriKey.D, d, t)
	if err != nil {
		return nil, err
	}
	// get D = H6(pk_a,pk_b,pk_b^a)
	D := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(&aPriKey.PublicKey),
				curve.PointToBytes(bPubKey)),
			curve.PointToBytes(curve.PointScalarMul(bPubKey, aPriKey.D))))
	KF := []KFrag{}
	for i := 0; i < N; i++ {
		Y, y, err := curve.KeyGen(isGM) //增加国密可选项
		if err != nil {
			return nil, err
		}
		//根据传入参数选择国密或国际曲线
		curve.InitCurve(isGM)
		id, err := ecdsa.GenerateKey(curve.GlobalCurve.Curve, rand.Reader)
		if err != nil {
			return nil, err
		}
		// get s_x = H5(id,D)
		s_x := utils.HashToCurve(
			utils.ConcatBytes(
				id.D.Bytes(),
				D.Bytes()))
		rk := utils.GetPolynomialValue(coefficients, s_x)
		U_1 := curve.BigIntMulBase(rk)
		// get z_1 = H4(Y,id,pk_a,pk_b,U_1,X_A)
		z_1 := utils.HashToCurve(
			utils.ConcatBytes(
				utils.ConcatBytes(
					utils.ConcatBytes(
						utils.ConcatBytes(
							utils.ConcatBytes(
								curve.PointToBytes(Y),
								id.D.Bytes()),
							curve.PointToBytes(&aPriKey.PublicKey)),
						curve.PointToBytes(bPubKey)),
					curve.PointToBytes(U_1)),
				curve.PointToBytes(X_A)))
		// get z_2 = y - a × z_1
		z_2 := math.BigIntSub(y.D, math.BigIntMul(aPriKey.D, z_1))
		kFrag := KFrag{
			Id:  id,
			Rk:  rk,
			X_A: X_A,
			U_1: U_1,
			z_1: z_1,
			z_2: z_2,
			C:   curve.BigIntMulBase(condition),
			T:   math.BigIntMul(condition, math.GetInvert(utils.HashToCurve(curve.PointToBytes(curve.BigIntMulBase(big.NewInt(int64(t))))))),
		}
		KF = append(KF, kFrag)
	}
	// KF长度为N
	return KF, nil
}

func ReEncapsulate(kFrag KFrag, capsule *Capsule) (*CFrag, error) {
	if !kFrag.C.Equal(capsule.C) {
		return nil, fmt.Errorf("%s", "condition not match")
	}
	cFrag := CFrag{
		E_1: curve.PointScalarMul(capsule.E, kFrag.Rk),
		V_1: curve.PointScalarMul(capsule.V, kFrag.Rk),
		id:  kFrag.Id,
		X_A: kFrag.X_A,
		T:   kFrag.T,
	}
	return &cFrag, nil
}

func ReEncrypt(KF []KFrag, cipher *Cipher_before_re) (*Cipher_after_re, error) {
	CF := []CFrag{}
	l := len(KF)
	for i := 0; i < l; i++ {
		cFrag, err := ReEncapsulate(KF[i], cipher.Capsule)
		if err != nil {
			return nil, err
		}
		CF = append(CF, *cFrag)
	}
	re_cipher := &Cipher_after_re{
		CF:         CF,
		CipherText: cipher.CipherText,
	}
	return re_cipher, nil
}

// 让每个节点独立执行该步骤，为了最小化改动，传入的KF数组中指包含一个元素（即每个节点持有的密钥碎片），且返回每个节点自己的执行结果
func NewReEncrypt(KF KFrag, cipher *Cipher_before_re) (*CFrag, error) {
	cFrag, err := ReEncapsulate(KF, cipher.Capsule)
	if err != nil {
		return nil, err
	}
	return cFrag, nil
}

func DecapsulateFrags(bPriKey *ecdsa.PrivateKey, aPubKey *ecdsa.PublicKey, CF []CFrag, isGM bool) ([]byte, error) {
	// get D = H6(pk_a,pk_b,pk_a^b)
	D := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(aPubKey),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(curve.PointScalarMul(aPubKey, bPriKey.D))))
	// 此处假设传入的CF切片长度为t
	t := len(CF)
	s_x := []*big.Int{}
	for i := 0; i < t; i++ {
		s_x_i := utils.HashToCurve(
			utils.ConcatBytes(
				CF[i].id.D.Bytes(),
				D.Bytes()))
		s_x = append(s_x, s_x_i)
	}
	lamda_S := []*big.Int{}
	for i := 1; i <= t; i++ {
		lamda_i_S := big.NewInt(1)
		for j := 1; j <= t; j++ {
			if j == i {
				continue
			} else {
				lamda_i_S = math.BigIntMul(lamda_i_S, (math.BigIntMul(s_x[j-1], math.GetInvert(math.BigIntSub(s_x[j-1], s_x[i-1])))))
			}
		}
		lamda_S = append(lamda_S, lamda_i_S)
	}
	E := curve.PointScalarMul(CF[0].E_1, lamda_S[0])
	V := curve.PointScalarMul(CF[0].V_1, lamda_S[0])
	for i := 1; i < t; i++ {
		E = curve.PointScalarAdd(E, curve.PointScalarMul(CF[i].E_1, lamda_S[i]))
		V = curve.PointScalarAdd(V, curve.PointScalarMul(CF[i].V_1, lamda_S[i]))
	}
	// get d = H3(X_A,pk_b,X_A^b)
	d := utils.HashToCurve(
		utils.ConcatBytes(
			utils.ConcatBytes(
				curve.PointToBytes(CF[0].X_A),
				curve.PointToBytes(&bPriKey.PublicKey)),
			curve.PointToBytes(curve.PointScalarMul(CF[0].X_A, bPriKey.D))))
	condition := math.BigIntMul(CF[0].T, utils.HashToCurve(curve.PointToBytes(curve.BigIntMulBase(big.NewInt(int64(t))))))
	point1 := curve.PointScalarMul(curve.PointScalarAdd(E, V), d)
	point := curve.PointScalarMul(point1, condition)
	keyBytes, err := utils.Sha3Hash(curve.PointToBytes(point), isGM) //增加国密可选
	if err != nil {
		return nil, err
	}
	return keyBytes, nil
}

func DecryptFrags(aPubKey *ecdsa.PublicKey, bPriKey *ecdsa.PrivateKey, re_cipher *Cipher_after_re, t int, encfileName string, decfileName string, isGM bool) (err error) {
	// 此处假设传入的CF切片长度为默认的N
	CF := []CFrag{}
	for i := 0; i < t; i++ {
		CF = append(CF, re_cipher.CF[i])
	}

	keyBytes, err := DecapsulateFrags(bPriKey, aPubKey, CF, isGM) //增加国密可选
	if err != nil {
		return err
	}
	key := hex.EncodeToString(keyBytes)
	err = OFBFileDecrypt(key[:32], keyBytes[:12], encfileName, decfileName)
	if err != nil {
		return err
	}
	return err
}

func NewDecryptFrags(aPubKey *ecdsa.PublicKey, bPriKey *ecdsa.PrivateKey, re_cipher *Cipher_after_re, t int, isGM bool) (plaintext string, err error) {
	// 此处假设传入的CF切片长度为默认的t
	if len(re_cipher.CF) < t {
		return "", errors.New(fmt.Sprintf("需要凑齐至少 %d 个碎片，目前没有凑齐", t))
	}

	CF := []CFrag{}
	for i := 0; i < t; i++ {
		CF = append(CF, re_cipher.CF[i])
	}
	keyBytes, err := DecapsulateFrags(bPriKey, aPubKey, CF, isGM) //增加国密可选
	if err != nil {
		return "", err
	}
	key := hex.EncodeToString(keyBytes)

	//按是否选用国密模式做区分,SM4的默认数据分块大小是16字节（128位）
	if isGM {
		plaintext, err = Sm4gcmDecrypt(key[:16], string(re_cipher.CipherText))
	} else {
		plaintext, err = aesgcmDecrypt(key[:32], string(re_cipher.CipherText))
	}

	if err != nil {
		return "", err
	}
	return plaintext, nil
}

// Sm4gcmEncrypt 增加基于SM4的GCM模式对称加密方法，与AES大致相同
func Sm4gcmEncrypt(secretKey string, plaintext string) ([]byte, error) {

	sm4, err := sm4.NewCipher([]byte(secretKey))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(sm4)
	if err != nil {
		return nil, err
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return ciphertext, nil
}

// Sm4gcmDecrypt 增加基于SM4的GCM模式对称解密方法，与AES大致相同
func Sm4gcmDecrypt(secretKey string, ciphertext string) (string, error) {
	sm4, err := sm4.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(sm4)
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
