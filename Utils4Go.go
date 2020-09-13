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
	"path/filepath"
	"strings"
)

func main() {}

//General Stuff----------------------------------------------------------------------
func GetObj(anyType interface{}, e error) interface{} {
	Check(e)
	return anyType
}
func Check(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

//String Stuff
func Contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
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

//File Stuff--------------------------------------------------------------------------
func ReadFile(filePath string) []byte {
	return GetObj(ioutil.ReadFile(filePath)).([]byte)
}
func getAllFiles(root string) []string {
	var files []string
	err := filepath.Walk(root, func(absoluteFilePath string, info os.FileInfo, err error) error {
		files = append(files, absoluteFilePath)
		return nil
	})
	if err != nil {
		panic(err)
	}
	return files
}

//Console Stuff-----------------------------------------------------------------------
func Readline(output string) string {
	fmt.Print(output)
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	Check(err)
	input = strings.Replace(input, "\n", "", -1)
	input = strings.Replace(input, "\r", "", -1)
	return input
}

//Json Stuff--------------------------------------------------------------------------
func ParseJSONFileToMap(filePath string) map[string]interface{} {
	file, _ := os.Open(filePath)
	defer file.Close()
	bytes, _ := ioutil.ReadAll(file)
	var fileAsJSON map[string]interface{}
	json.Unmarshal(bytes, &fileAsJSON)
	return fileAsJSON
}
func GetJsonValue(target interface{}, key string) interface{} {
	return target.(map[string]interface{})[key]
}
func FetchGetResponse(request string) map[string]interface{} {
	raw := GetObj(http.Get(request)).(*http.Response)
	data := GetObj(ioutil.ReadAll(raw.Body)).([]byte)
	var response map[string]interface{}
	json.Unmarshal(data, &response)
	return response
}
