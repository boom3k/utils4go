package utils4go

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)
func main(){}

//General Stuff--------------------------------------------------------------------
func GetObj(anyType interface{}, e error) interface{} {
	check(e)
	return anyType
}
func ReadFile(filePath string) []byte {
	return GetObj(ioutil.ReadFile(filePath)).([]byte)
}
func check(err error) {
	if err != nil {
		fmt.Println(err)
	}
}
func PrintAll(list []string) {
	for _, s := range list {
		fmt.Println(s)
	}
}

//Encryption Stuff--------------------------------------------------------------------
func DecryptString(cipherstring string, keystring string) string {
	// Byte array of the string
	ciphertext := []byte(cipherstring)

	// Key
	key := []byte(keystring)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Before even testing the decryption,
	// if the text is too small, then it is incorrect
	if len(ciphertext) < aes.BlockSize {
		panic("Text is too short")
	}

	// Get the 16 byte IV
	iv := ciphertext[:aes.BlockSize]

	// Remove the IV from the ciphertext
	ciphertext = ciphertext[aes.BlockSize:]

	// Return a decrypted stream
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt bytes from ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext)
}
func EncryptString(plainstring, keystring string) string {
	// Byte array of the string
	plaintext := []byte(plainstring)

	// Key
	key := []byte(keystring)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Empty array of 16 + plaintext length
	// Include the IV at the beginning
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// Slice of first 16 bytes
	iv := ciphertext[:aes.BlockSize]

	// Write 16 rand bytes to fill iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// Return an encrypted stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// EncryptString bytes from plaintext to ciphertext
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return string(ciphertext)
}

//Console Stuff--------------------------------------------------------------------
func ReadLine(output string) string {
	fmt.Print(output)
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	check(err)
	return strings.TrimSuffix(input, "\r\n")
	//return strings.Replace(input, "\r\n", "", -1)
}

//Json Stuff--------------------------------------------------------------------
func ReadJsonFile(filePath string) map[string]interface{} {
	jsonFile, err := os.Open(filePath)
	check(err)
	fmt.Println("Successfully Opened: " + filePath)
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	var result map[string]interface{}
	json.Unmarshal(byteValue, &result)
	return result

}
func GetJsonKey(target interface{}, key string) interface{} {
	return target.(map[string]interface{})[key]
}
func FetchGetResponse(request string) map[string]interface{} {
	raw := GetObj(http.Get(request)).(*http.Response)
	data := GetObj(ioutil.ReadAll(raw.Body)).([]byte)
	var response map[string]interface{}
	json.Unmarshal(data, &response)
	return response
}
