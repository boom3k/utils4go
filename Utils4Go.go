package utils4go

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
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
func GetObj(anyType interface{}, e error, killOnErr bool) interface{} {
	CatchException(e, killOnErr)
	return anyType
}
func CatchException(err error, killOnErr bool) {
	if err != nil {
		log.Println(err.Error())
		if killOnErr {
			panic(err)
		}
	}
}

/*String Stuff-----------------------------------------------------------------------*/
func SliceContains(slice []interface{}, target interface{}) bool {
	for _, a := range slice {
		if a == target {
			return true
		}
	}
	return false
}

func StringSliceContains(slice []string, target string, ignoreCase bool) bool {
	for _, s := range slice {
		if !ignoreCase {
			s = strings.ToLower(s)
			target = strings.ToLower(target)
		}
		if s == target {
			return true
		}
	}
	return false
}

/*Encryption Stuff--------------------------------------------------------------------*/
func DecryptString(cipherstring string, keystring string) (string, error) {
	// Byte array of the string
	ciphertext := []byte(cipherstring)

	// Key
	key := []byte(keystring)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Before even testing the decryption,
	// if the text is too small, then it is incorrect
	if len(ciphertext) < aes.BlockSize {
		log.Println("Cipher text is too short")
		return "", nil
	}

	// Get the 16 byte IV
	iv := ciphertext[:aes.BlockSize]

	// Remove the IV from the ciphertext
	ciphertext = ciphertext[aes.BlockSize:]

	// Return a decrypted stream
	stream := cipher.NewCFBDecrypter(block, iv)

	// Decrypt bytes from ciphertext
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}
func EncryptString(plainstring, keystring string) (string, error) {
	// Byte array of the string
	plaintext := []byte(plainstring)

	// Key
	key := []byte(keystring)

	// Create the AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil
	}

	// Empty array of 16 + plaintext length
	// Include the IV at the beginning
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	// Slice of first 16 bytes
	iv := ciphertext[:aes.BlockSize]

	// Write 16 rand bytes to fill iv
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Return an encrypted stream
	stream := cipher.NewCFBEncrypter(block, iv)

	// EncryptString bytes from plaintext to ciphertext
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return string(ciphertext), err
}

/*File Stuff--------------------------------------------------------------------------*/
func ReadFile(filePath string) []byte {
	data, err := ioutil.ReadFile(filePath)
	CatchException(err, true)
	return data

}
func GetAllFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(absoluteFilePath string, info os.FileInfo, err error) error {
		files = append(files, absoluteFilePath)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
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
	log.Print(output)
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		panic(err)
	}
	input = strings.Replace(input, "\n", "", -1)
	input = strings.Replace(input, "\r", "", -1)
	log.Print(input)
	return input
}

/*Log Stuff ---------------------------------------------------------------------------*/
func SetNativeLogger(logfileName string) *os.File {
	log.Println("Logging to file: " + logfileName)
	f, err := os.OpenFile(logfileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	mw := io.MultiWriter(os.Stdout, f)
	log.SetOutput(mw)
	return f
}

/*CSV Stuff ---------------------------------------------------------------------------*/
func GetValuesFromCSVFile(csvFilePath string) [][]interface{} {
	log.Println("Reading csv file: " + csvFilePath)
	var csvValues [][]interface{}
	csvFile, _ := os.Open(csvFilePath)
	reader := csv.NewReader(bufio.NewReader(csvFile))
	for {
		var rowData []interface{}
		row, error := reader.Read()
		if error == io.EOF {
			break
		} else if error != nil {
			log.Println(error.Error())
			panic(error)
		}
		for column := range row {
			rowData = append(rowData, row[column])
		}
		csvValues = append(csvValues, rowData)
	}
	log.Println("Returning [" + fmt.Sprint(len(csvValues)) + "] rows from " + csvFilePath)
	return csvValues
}
func ConvertInterfaceSheetValuesToStrings(sheetWriteValues [][]interface{}) [][]string {
	var result [][]string
	for row := range sheetWriteValues {
		var rowData []string
		for column := range sheetWriteValues[row] {
			rowData = append(rowData, fmt.Sprint(sheetWriteValues[row][column]))
		}
		result = append(result, rowData)
	}
	return result
}
func ConvertStringSheetValuesToInterfaces(sheetWriteValues [][]string) [][]interface{} {
	var result [][]interface{}
	for row := range sheetWriteValues {
		var rowData []interface{}
		for column := range sheetWriteValues[row] {
			rowData = append(rowData, fmt.Sprint(sheetWriteValues[row][column]))
		}
		result = append(result, rowData)
	}
	return result
}
func WriteToCSV(csvWriteValues [][]interface{}, fileName string) {
	csvFile, csvCreateErr := os.Create(fileName)
	if csvCreateErr != nil {
		log.Println(csvCreateErr.Error())
		panic(csvCreateErr)
	}
	writer := csv.NewWriter(csvFile)
	defer writer.Flush()
	for _, value := range ConvertInterfaceSheetValuesToStrings(csvWriteValues) {
		writerErr := writer.Write(value)
		if writerErr != nil {
			log.Println(writerErr.Error())
			panic(writerErr)
		}
	}
}

/*Json Stuff--------------------------------------------------------------------------*/
func ParseJSONFileToMap(filePath string) (map[string]interface{}, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
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
	raw, err := http.Get(request)
	if err != nil {
		panic(err)
	}
	data, err := ioutil.ReadAll(raw.Body)
	if err != nil {
		panic(err)
	}
	var response map[string]interface{}
	json.Unmarshal(data, &response)
	return response
}

/*Timer Stuff--------------------------------------------------------------------------*/
func TrackFunction(functionName string) (string, time.Time) {
	return functionName, time.Now()
}
func Duration(msg string, start time.Time) string {
	timeTaken = time.Since(start)
	log.Println(msg + " completed in: " + fmt.Sprint(timeTaken))
	return fmt.Sprint(timeTaken)
}
func GetTimeTaken() time.Duration {
	return timeTaken
}

/*IP Stuff-----------------------------------------------------------------------------*/
func GetExternalIp() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
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
			panic(err)
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
			return ip.String()
		}
	}
	return "Are you connected to a network?"
}
