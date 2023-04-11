package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
)

func createSignature(secretKey string, message []byte) string {
	key := []byte(secretKey)
	h := hmac.New(sha1.New, key)
	h.Write(message)
	return hex.EncodeToString(h.Sum(nil))
}

// func encrypt(plainText, key []byte) (string, error) {
// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}

// 	cipherText := make([]byte, aes.BlockSize+len(plainText))
// 	iv := cipherText[:aes.BlockSize]
// 	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
// 		return "", err
// 	}

// 	stream := cipher.NewCFBEncrypter(block, iv)
// 	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

// 	return base64.StdEncoding.EncodeToString(cipherText), nil
// }

func encrypt(plainText string, password string) string {
	// 使用密码生成密钥
	key := sha256.Sum256([]byte(password))

	// 生成随机初始化向量 (IV)
	block, _ := aes.NewCipher(key[:])
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// PKCS7 填充
	padding := aes.BlockSize - len(plainText)%aes.BlockSize
	paddedPlainText := append([]byte(plainText), bytes.Repeat([]byte{byte(padding)}, padding)...)

	// 加密
	encrypted := make([]byte, len(paddedPlainText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, paddedPlainText)

	// 将 IV 和加密后的密文进行拼接，然后进行 Base64 编码
	return base64.StdEncoding.EncodeToString(append(iv, encrypted...))
}

// func decrypt(cipherText string, key []byte) (string, error) {
// 	data, err := base64.StdEncoding.DecodeString(cipherText)
// 	if err != nil {
// 		return "", err
// 	}

// 	block, err := aes.NewCipher(key)
// 	if err != nil {
// 		return "", err
// 	}

// 	if len(data) < aes.BlockSize {
// 		return "", fmt.Errorf("ciphertext too short")
// 	}

// 	iv := data[:aes.BlockSize]
// 	data = data[aes.BlockSize:]

// 	stream := cipher.NewCFBDecrypter(block, iv)

// 	stream.XORKeyStream(data, data)

// 	return string(data), nil
// }

func decrypt(cipherText string, password string) string {
	// 使用密码生成密钥
	key := sha256.Sum256([]byte(password))

	// 对 Base64 编码的密文进行解码
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		panic(err)
	}

	// 提取 IV
	block, _ := aes.NewCipher(key[:])
	iv := cipherBytes[:aes.BlockSize]

	// 解密
	decrypted := make([]byte, len(cipherBytes[aes.BlockSize:]))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, cipherBytes[aes.BlockSize:])

	// 移除 PKCS7 填充
	padding := int(decrypted[len(decrypted)-1])
	return string(decrypted[:len(decrypted)-padding])
}

type TaskCmd struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Hostname string `json:"hostname"`
	Command  string `json:"command"`
}

func main() {
	// 将这里的 URL 替换为你的 Flask API 的实际 URL
	url := "http://localhost:8000/execute"

	plainText := "lxw123456@"
	key := "7d07d0f0e05c47f08b4c7a6b7fcb0fb3"
	encrypted := encrypt(plainText, key)

	fmt.Println("Encrypted password:", encrypted)

	taskCmd := TaskCmd{
		Username: "root",
		Password: encrypted,
		Hostname: "192.168.1.10",
		Command:  "ls",
	}

	decrypted := decrypt(encrypted, key)

	fmt.Println("decrypted password:", decrypted)

	jsonData, _ := json.Marshal(taskCmd)

	// 使用指定的密钥计算签名
	secretKey := "your-secret-key"
	signature := createSignature(secretKey, jsonData)

	// 创建 HTTP POST 请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}

	// 设置请求头，如 Content-Type 和 X-Signature 等
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("OSP-Signature", signature)

	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	// 输出响应内容
	fmt.Printf("Response status: %s\n", resp.Status)
	fmt.Printf("Response body: %s\n", string(body))
}
