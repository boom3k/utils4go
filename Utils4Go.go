package utils4go

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
}

var timeTaken time.Duration
var log2FileDebug = false

/*General Stuff----------------------------------------------------------------------*/
func GetObj(anyType interface{}, e error) interface{} {
	CatchException(e)
	return anyType
}
func CatchException(err error) {
	if err != nil {
		panic(err)
		log.Fatalf(err.Error())
	}
}

/*String Stuff-----------------------------------------------------------------------*/
func SliceContains(s []interface{}, e interface{}) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

/*Encryption Stuff--------------------------------------------------------------------*/
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

/*File Stuff--------------------------------------------------------------------------*/
func ReadFile(filePath string) []byte {
	return GetObj(ioutil.ReadFile(filePath)).([]byte)
}
func GetAllFiles(root string) []string {
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
func ByteCount(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB",
		float64(b)/float64(div), "kMGTPE"[exp])
}
func ByteCountIEC(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB",
		float64(b)/float64(div), "KMGTPE"[exp])
}
func WriteToFile(filename string, data string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, data)
	if err != nil {
		return err
	}
	return file.Sync()
}

/*Console Stuff-----------------------------------------------------------------------*/
func Readline(output string) string {
	Log2File(output)
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	CatchException(err)
	input = strings.Replace(input, "\n", "", -1)
	input = strings.Replace(input, "\r", "", -1)
	return input
}
func EnabledLog2FileDebug() {
	log2FileDebug = true
}
func Log2File(output string) string {
	time := time.Now().Format("Mon Jan _2 2006 15:04:05") + " - "
	f, err := os.OpenFile("runner.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	CatchException(err)
	defer f.Close()
	f.WriteString(time + output)
	if log2FileDebug == true {
		fmt.Print(time + output)
	} else {
		fmt.Print(output)
	}

	return output
}
func Log2FileLn(outputLn string) {
	Log2File(outputLn + "\n")
}

/*Json Stuff--------------------------------------------------------------------------*/
func ParseJSONFileToMap(filePath string) (map[string]interface{}, error) {
	file, err := os.Open(filePath)
	if err != nil {
		panic(err)
		return nil, err
	}
	defer file.Close()
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
		return nil, err
	}
	var fileAsJSON map[string]interface{}
	json.Unmarshal(bytes, &fileAsJSON)
	return fileAsJSON, nil
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

/*Timer Stuff--------------------------------------------------------------------------*/
func TrackFunction(functionName string) (string, time.Time) {
	return functionName, time.Now()
}
func Duration(msg string, start time.Time) {
	timeTaken = time.Since(start)
	Log2FileLn(msg + " completed in: " + fmt.Sprint(timeTaken))
}
func GetTimeTaken() time.Duration {
	return timeTaken
}

/*IP Stuff-----------------------------------------------------------------------------*/
func GetExternalIp() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New(" are you connected to the network?")
}
