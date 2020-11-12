package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

var (
	originPubKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2K+PRbp/yumhaVnN92JS
GuQiwj7df64jHAo8MvXLWjYxU/yvqB4LbGty8ymKQy33qaDNpu9jgE2s8cXrtftm
/UcvwDb8sTqWXpDhxYhcvJM30agxz3/8VwNJ4JOvhk9Gn+msYIUz+gXZMBuUFKhi
BOd6C2Pro03GYwVTNjfwH/Y9C5EfPKIKNU/5t2cYo+TuOBk5ooP+NTaDzB6rb7fd
E5uuNnF21x3rdiI9rZcKPbuU97/0OWNcIUh5wfxPNWwcmjYmFuZcxk/7dOUD65s4
pTplCoMLOelacB0l442dM4w2xNpn+Yg7i/ujmg37F+VguCZJWnoyImdhp/raccNG
+wIDAQAB
-----END PUBLIC KEY-----`
	newPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtKvyFB24hIEVwMs4Xi00
FCW41tqELGYb7f63A/lAsBPVSOvGrQ5UzuKmttatQF/IDD9UcHqqbi+B80pydiGS
eKJOaly0GuX6hfDd51/uo7E44LyzJSSBhTc1vtbL5JbNcapnxo4P6rJ1Uh9V7y8z
pRvc1G2da00mQSYoIg/9ty21j4So+Fz/v37qhK50EEIeXGJZb4uz9I9iKCHaazjI
Lf293Gzvp7EFEpZkKrh2VktKaERh+jHmJqEe0z7U/sz0cCa9ohS+TF5nxmkAZBel
CwEMXjkjGnCWO3wXJoyrXMn1GY/ilNPDFT7rSZBKLEIi7PrBD1pVLGdq2zTboenV
6wIDAQAB
-----END PUBLIC KEY-----`
	newPrivateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAtKvyFB24hIEVwMs4Xi00FCW41tqELGYb7f63A/lAsBPVSOvG
rQ5UzuKmttatQF/IDD9UcHqqbi+B80pydiGSeKJOaly0GuX6hfDd51/uo7E44Lyz
JSSBhTc1vtbL5JbNcapnxo4P6rJ1Uh9V7y8zpRvc1G2da00mQSYoIg/9ty21j4So
+Fz/v37qhK50EEIeXGJZb4uz9I9iKCHaazjILf293Gzvp7EFEpZkKrh2VktKaERh
+jHmJqEe0z7U/sz0cCa9ohS+TF5nxmkAZBelCwEMXjkjGnCWO3wXJoyrXMn1GY/i
lNPDFT7rSZBKLEIi7PrBD1pVLGdq2zTboenV6wIDAQABAoIBAQCu3PSxr4pVBLLP
JGFsFQggr9nUaS4f4rwJfswXlnibcratmzVxbTt7+TYuJF0OvyVZZToOm0q01lpJ
5LYfy6J+C2kl3I+csRXl6Rh8xgase+x252vj+Q86phLon/A7UBGLf8htDjYti4et
chK0KtUramozV9xSbBsoVwvk2+FOFdiLsc+B3PyuydB0Lvov5EDBtZJ1GbnyWk/3
c++aL+lkjQbIs11A4Nwp7hUdPmM/Va8VK+DqWxbFCIr6rli5d9VOE//EHJ7S7aPp
+fxV9gyv1d0WBRNktH2t8O2JVn90379/EgWuonSlRG+HrhqZKrXIKuIFJEUmGUjs
8qJNzoERAoGBAOLjiGbXuOQHkshDqdB4xF1b4rvCBrr881dBAOnYqSyEUWuUD3et
4qX/7GaxWlSU2IteB+r5FyfEpmqUNmKVsgLkGh3lgeTU0Mss2+2xIAODNXvba8MV
UIawpvDFnLN2HEY/d+LYycBjWDk+6B1+dGlPZIxXF+8HqGnlqyBNFjP/AoGBAMva
WVB02FK4oXa8APTtvuQ2MP67Q95WdhZXdy8CEWnwJaknSTE3dXJ9nZZmFgHt54lo
KjbGfIOSCLeCqXm3ZGs5HQr2kY/xJXDJga6uNh71w66/q/W2z+30FFzta6BjYE/8
3pB+P4vUUsp/vb3SkNfRKdcNrtoL29UYdXM7QG4VAoGAQqLw/MN+2fofchHtXf0a
LxE9lkd2EpUYIxhEXGn1xc1W3HGv2UaIuphfpgmQribJMqV7Tde6pUNsXQEKuAmf
Lpov0XgGnl6itAmIzlanQGDY5HedPr6T1/sqDKz9SPf3depOG6HwH0EOOEHxijgJ
mKRos48gyGNHY1LA38vEKaECgYEAmu8fRsknyOdOwMFvMLiphyWw40pM8OVh5uUf
TnkR5ySAWynitSdjelsCtNZuD5VTjtm+i9cbt5v8SA1k5X9/MQc9jaGNTIuJW0mr
6Km7tJgx29UNyzjgnAgQmfhQ/pvJDcIxHjz16z66lfG0slshfwYX+L0LkenFcRaf
3a7A72kCgYEAhSSGHVkCTGteSyKxhbMVqTlxQQQWZKv4b+usqss00CKgs3CAKL8H
Crds7fq96xVDVCvxJGYMKQzG61MBa+e1f8YSdhl5EY1IltlHkZstgts7avG6MP6A
xMNjyLp1b84s2VVXTpSFA7i6KEUhl4NjqhZTslJht5Dfiy2Mmvfk2so=
-----END RSA PRIVATE KEY-----`
	licenseVersion2Byte = []byte{0x02}
	pre2Bytes           = []byte{0x00, 0x01}
	aesKeyNew, _        = hex.DecodeString("B293C506E0C7F60353C604961837B810")
)

var (
	licenseName   string
	originLicense string
	xrayFilePath  string
)

func main() {
	flag.StringVar(&licenseName, "g", "", "生成一个永久license，需要指定用户名")
	flag.StringVar(&originLicense, "p", "", "解析官方证书，需要指定证书路径")
	flag.StringVar(&xrayFilePath, "c", "", "patch xray，需要指定xray程序文件路径")

	flag.Parse()

	if originLicense != "" {
		parseAlready(originLicense)
	}

	if licenseName != "" {
		genNew(licenseName)
	}

	if xrayFilePath != "" {
		patch(xrayFilePath)
	}

}

func parseAlready(licenseFile string) {
	// 加载公钥
	pubKey := importPublicKey(originPubKeyPem)

	// 解析 xray-license.lic 文件
	licenseFileData, err := ioutil.ReadFile(licenseFile)
	if err != nil {
		panic(err.Error())
	}
	licenseString := string(licenseFileData)
	tmpStrings := strings.Split(licenseString, "\n")
	licenseString = ""
	for _, line := range tmpStrings {
		if !strings.HasPrefix(line, "#") && line != "" {
			licenseString += line
		}
	}
	//fmt.Println("your license:", licenseString)

	base64DecodeData, err := base64.StdEncoding.DecodeString(licenseString)
	if err != nil {
		panic(err)
	}

	//fmt.Println("base64 decode data:", hex.EncodeToString(base64DecodeData))

	licenseVersion := base64DecodeData[0]
	if licenseVersion == 2 {
		fmt.Println("version ok: 2")
	}

	//解密前有一个简单的变换处理
	right := len(base64DecodeData) - 1
	for l := 1; l < right; l++ {
		r := right - l
		if l >= r {
			break
		}
		base64DecodeData[l], base64DecodeData[r] = base64DecodeData[r], base64DecodeData[l]
	}
	//fmt.Println("trans bytes:", hex.EncodeToString(base64DecodeData))

	// aes解密license
	// | 1B : version | 16B : aes iv | 480B : cipher |
	aesDecData, err := Decrypt(base64DecodeData[17:], base64DecodeData[1:17])
	if err != nil {
		panic(err)
	}
	//fmt.Printf("AES DEC: %x\n", aesDecData)
	//fmt.Println(string(aesDecData))

	//另一个异或变换
	for i := 0; i < len(aesDecData); i++ {
		aesDecData[i] = aesDecData[i] ^ 0x44
	}
	//fmt.Println("trans 2 :", hex.EncodeToString(aesDecData))
	//fmt.Println("trans 2 string:", string(aesDecData))

	// 后半部分是明文的json
	licensePlainJsonBytes := aesDecData[0x102:]
	//fmt.Println("license info json:", string(licensePlainJsonBytes))
	//fmt.Println("pre2bytes：", hex.EncodeToString(aesDecData[:0x2]))

	license := License{}
	err = json.Unmarshal([]byte(licensePlainJsonBytes), &license)
	if err != nil {
		panic(err)
	}
	fmt.Println("license parsed:", license)

	// rsa 验证签名 pss
	sum := sha256.Sum256(licensePlainJsonBytes)
	//fmt.Println(sum)

	// rsa使用 sha256算法，对 aes解密后的数据第三个字节开始，到后面json明文前面为止是签名
	//fmt.Println("解析出来的签名：", aesDecData[2:0x102])

	err = rsa.VerifyPSS(pubKey, crypto.SHA256, sum[:], aesDecData[2:0x102], nil)
	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("varify success")
	}
}

func genNew(name string) {
	validTime, err := time.Parse("2006-01-02 15:04:05", "2099-09-09 00:00:00")

	license := License{
		LicenseId:      "00000000000000000000000000000000",
		UserId:         "00000000000000000000000000000000",
		UserName:       name,
		Distribution:   "COMMUNITY-ADVANCED",
		NotValidBefore: 1591891200,
		NotValidAfter:  validTime.Unix(),
	}

	licensePlainJsonBytes, _ := json.Marshal(license)
	//licensePlainJson := string(licensePlainJsonBytes)
	//fmt.Println("明文license信息：", licensePlainJson)

	// rsa sign
	priKey := importPrivateKey(newPrivateKeyPem)

	//sha256sum
	sum := sha256.Sum256(licensePlainJsonBytes)
	signature, err := rsa.SignPSS(rand.Reader, priKey, crypto.SHA256, sum[:], nil)
	if err != nil {
		panic(err)
	}

	licenseInfoWithSign := append(signature, licensePlainJsonBytes...)
	data2Enc := append(pre2Bytes, licenseInfoWithSign...)

	// 加密前一次异或
	for i := 0; i < len(data2Enc); i++ {
		data2Enc[i] = data2Enc[i] ^ 0x44
	}

	// session iv
	iv := make([]byte, 16)
	_, _ = rand.Read(iv)
	fmt.Println("temp aes iv:", hex.EncodeToString(iv))
	aesEnc, err := Encrypt(data2Enc, iv)
	if err != nil {
		panic(err)
	}
	//fmt.Println(aesEnc)

	allBytes := append(iv, aesEnc...)
	allBytes = append(licenseVersion2Byte, allBytes...)

	// 左右交换
	right := len(allBytes) - 1
	for l := 1; l < right; l++ {
		r := right - l
		if l >= r {
			break
		}
		allBytes[l], allBytes[r] = allBytes[r], allBytes[l]
	}

	licenseText := base64.StdEncoding.EncodeToString(allBytes)

	fileText := `# xray license
# 需要重命名为 xray-license.lic 和 xray 可执行程序放在同一个文件夹中
# user_name: Chinese
# distribution: COMMUNITY-ADVANCED
# 仅对修改后的xray有效
` + licenseText + `
`

	err = ioutil.WriteFile("xray-license.lic", []byte(fileText), os.ModePerm)
	if err == nil {
		fmt.Println("证书已写入文件：xray-license.lic")
	}
}

func Decrypt(decodeData []byte, iv []byte) ([]byte, error) {
	block, _ := aes.NewCipher(aesKeyNew)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origin_data := make([]byte, len(decodeData))
	blockMode.CryptBlocks(origin_data, decodeData)
	return unpad(origin_data), nil
}

func unpad(ciphertext []byte) []byte {
	length := len(ciphertext)
	unpadding := int(ciphertext[length-1])
	return ciphertext[:(length - unpadding)]
}

func Encrypt(text []byte, iv []byte) ([]byte, error) {
	block, _ := aes.NewCipher(aesKeyNew)
	blockSize := block.BlockSize()
	originData := pad(text, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(originData))
	blockMode.CryptBlocks(crypted, originData)
	//fmt.Println(len(originData))
	return crypted, nil
}

func pad(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

type License struct {
	LicenseId      string `json:"license_id"`
	UserId         string `json:"user_id"`
	UserName       string `json:"user_name"`
	Distribution   string `json:"distribution"`
	NotValidBefore int64  `json:"not_valid_before"`
	NotValidAfter  int64  `json:"not_valid_after"`
}

func importPublicKey(key string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		panic("unable to decode publicKey to request")
	}

	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return pub.(*rsa.PublicKey)
}

func importPrivateKey(key string) *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(key))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return privateKey
}

var (
	origin386Bytes, _     = hex.DecodeString("0F95C083F0018844245083C430C3")
	new386Bytes, _        = hex.DecodeString("0F94C083F0018844245083C430C3")
	originAmd64Bytes, _   = hex.DecodeString("000F84BE020000")
	newAmd64Bytes, _      = hex.DecodeString("000F85BE020000")
	originArmBytes, _     = hex.DecodeString("000050E30000A0E30100A013010020E254")
	newArmBytes, _        = hex.DecodeString("000050E30000A0E30100A0130100A0E354")
	originAArch64Bytes, _ = hex.DecodeString("1F001FEBE0079F9A000040D2E0C3")
	newAArch64Bytes, _    = hex.DecodeString("1F001FEBE0079F9A200080D2E0C3")
)

func patch(filePath string) {
	var (
		originBytes []byte
		newBytes    []byte
		maxIndex    uint64 = 0
	)

	if elfFile, err := elf.Open(filePath); err == nil {
		switch elfFile.Machine {
		case elf.EM_386:
			fmt.Println("linux 386")
			originBytes = origin386Bytes
			newBytes = new386Bytes
		case elf.EM_X86_64:
			fmt.Println("linux amd64")
			originBytes = originAmd64Bytes
			newBytes = newAmd64Bytes
		case elf.EM_ARM:
			fmt.Println("linux arm")
			originBytes = originArmBytes
			newBytes = newArmBytes
		case elf.EM_AARCH64:
			fmt.Println("linux arm64")
			originBytes = originAArch64Bytes
			newBytes = newAArch64Bytes
		default:
			fmt.Println("Unsupported linux platform!!")
		}
		sections := elfFile.Sections
		for _, i := range sections {
			if i.Name == ".text" {
				maxIndex = i.Addr + i.Size
				fmt.Printf("[.text] offset: %#x, addr: %#x-%#x\n", i.Offset, i.Addr, maxIndex)
			}
		}
	} else if peFile, err := pe.Open(filePath); err == nil {
		switch peFile.Machine {
		case pe.IMAGE_FILE_MACHINE_AMD64:
			fmt.Println("windows amd64")
			originBytes = originAmd64Bytes
			newBytes = newAmd64Bytes
		case pe.IMAGE_FILE_MACHINE_I386:
			fmt.Println("windows i386")
			originBytes = origin386Bytes
			newBytes = new386Bytes
		default:
			fmt.Println("Unsupported windows platform!!")

		}
	} else if machoFile, err := macho.Open(filePath); err == nil {
		switch machoFile.Cpu {
		case macho.CpuAmd64:
			fmt.Println("darwin amd64")
			originBytes = originAmd64Bytes
			newBytes = newAmd64Bytes
		case macho.Cpu386:
			fmt.Println("darwin 386")
			originBytes = origin386Bytes
			newBytes = new386Bytes
		default:
			fmt.Println("Unsupported darwin platform!!")
		}
	} else {
		fmt.Println("Can NOT parse file")
		return
	}

	origin, err := ioutil.ReadFile(filePath)
	loc := bytes.LastIndex(origin, originBytes)

	if loc > 0 {
		fmt.Printf("Signature index: %#x\n", loc)
		newFile := replace(origin, newBytes, loc)
		err = ioutil.WriteFile(filePath, newFile, os.ModePerm)
		if err == nil {
			fmt.Println("Patch success:", filePath)
		}
	} else {
		fmt.Println("Can't find signature")
	}
}

func replace(origin, new []byte, index int) []byte {
	n := make([]byte, len(origin))
	copy(n[:index], origin[:index])
	copy(n[index:index+len(new)], new)
	copy(n[index+len(new):], origin[index+len(new):])
	return n
}
