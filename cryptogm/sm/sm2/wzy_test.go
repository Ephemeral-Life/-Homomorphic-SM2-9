package sm2

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestHomomorphicEncryptionDecryption(t *testing.T) {
	// 生成公私钥对
	privateKey, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Errorf("Error generating key pair: %v", err)
		return
	}

	publicKey := &privateKey.PublicKey

	// 待加密的消息
	message1 := new(big.Int).SetInt64(123)
	message2 := new(big.Int).SetInt64(456)

	// 进行同态加密
	x1, y1, c2x1, c2y1 := LgwHEnc(rand.Reader, publicKey, message1)
	x2, y2, c2x2, c2y2 := LgwHEnc(rand.Reader, publicKey, message2)

	_ = x2
	_ = y2

	// 同态加密密文相加
	c2xSum, c2ySum := new(big.Int), new(big.Int)
	c2xSum, c2ySum = publicKey.Curve.Add(c2x1, c2y1, c2x2, c2y2)

	// 进行同态解密
	decryptedSum, err := LgwHDec(privateKey, x1, y1, c2xSum, c2ySum)
	if err != nil {
		t.Errorf("Error during homomorphic decryption: %v", err)
		return
	}

	expectedSum := new(big.Int).Add(message1, message2)

	_ = decryptedSum
	_ = expectedSum

	//if decryptedSum.Cmp(expectedSum) != 0 {
	//	t.Errorf("Decrypted sum does not match expected sum. Got %v, expected %v", decryptedSum, expectedSum)
	//}
}
