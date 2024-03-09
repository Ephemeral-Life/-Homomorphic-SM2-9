package main

import (
	"crypto/rand"
	"fmt"
	"github.com/xlcetc/cryptogm/sm/sm2"
	"math/big"
)

func main() {
	// 生成SM2密钥对
	privateKey, err := sm2.GenerateKey(rand.Reader) // 请确保您的sm2包中有GenerateKey函数
	if err != nil {
		fmt.Printf("生成密钥对时出错: %s\n", err)
		return
	}
	publicKey := &privateKey.PublicKey

	// 定义两个要加密的消息
	message1 := big.NewInt(15) // 第一个消息
	message2 := big.NewInt(30) // 第二个消息

	// 使用公钥对两个消息分别进行同态加密
	x1, y1, c2x1, c2y1 := sm2.LgwHEnc(rand.Reader, publicKey, message1)
	_, _, c2x2, c2y2 := sm2.LgwHEnc(rand.Reader, publicKey, message2)

	// 将两个密文相加
	c2xSum := new(big.Int).Add(c2x1, c2x2)
	c2ySum := new(big.Int).Add(c2y1, c2y2)

	// 使用私钥对加和的密文进行解密
	sum, err := sm2.LgwHDec(privateKey, x1, y1, c2xSum, c2ySum)
	if err != nil {
		fmt.Printf("解密时出错: %s\n", err)
		return
	}

	// 显示解密后的总和
	fmt.Printf("解密得到的消息总和: %d\n", sum)
}

//func main() {
//	// 生成SM2密钥对
//	privateKey, err := sm2.GenerateKey(rand.Reader) // 请确保您的sm2包中有GenerateKey函数
//	if err != nil {
//		fmt.Printf("生成密钥对时出错: %s\n", err)
//		return
//	}
//	publicKey := &privateKey.PublicKey
//
//	// 定义要加密的消息
//	message := big.NewInt(42) // 以42为例
//
//	// 使用公钥进行同态加密
//	x1, y1, c2x, c2y := sm2.LgwHEnc(rand.Reader, publicKey, message)
//
//	// 显示加密结果
//	fmt.Println("同态加密结果:")
//	fmt.Printf("C1: (%s, %s)\n", x1.String(), y1.String())
//	fmt.Printf("C2: (%s, %s)\n", c2x.String(), c2y.String())
//
//	// 使用私钥进行解密
//	m, err := sm2.LgwHDec(privateKey, x1, y1, c2x, c2y)
//	if err != nil {
//		fmt.Printf("解密时出错: %s\n", err)
//		return
//	}
//
//	// 显示解密结果
//	fmt.Printf("解密得到的消息: %d\n", m)
//}
