package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/hkdf"
)

///
/// Cipher definitions
///
func chk(err error) {
	if err != nil {
		panic(err)
	}
}

type CipherSuite struct {
	ID      uint16
	Name    string
	Nk      int
	Nn      int
	Hash    crypto.Hash
	NewAEAD func(key []byte) cipher.AEAD
}

func newGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	chk(err)

	gcm, err := cipher.NewGCM(block)
	chk(err)

	return gcm
}

type AESCTRHMAC struct {
	Block   cipher.Block
	AuthKey []byte
	Hash    crypto.Hash
	TagSize int
}

func newAESCTRHMAC(key []byte, hash crypto.Hash, encSize, tagSize int) AESCTRHMAC {
	secret := hkdf.Extract(hash.New, key, []byte("SFrame10 AES CTR AEAD"))

	encKey := make([]byte, encSize)
	hkdf.Expand(hash.New, secret, []byte("enc")).Read(encKey)

	authKey := make([]byte, hash.Size())
	hkdf.Expand(hash.New, secret, []byte("auth")).Read(authKey)

	block, err := aes.NewCipher(encKey)
	chk(err)

	return AESCTRHMAC{block, authKey, hash, tagSize}
}

func (ctr AESCTRHMAC) NonceSize() int {
	return 12
}

func (ctr AESCTRHMAC) Overhead() int {
	return ctr.TagSize
}

func (ctr AESCTRHMAC) crypt(nonce, pt []byte) []byte {
	iv := append(nonce, []byte{0, 0, 0, 0}...)
	stream := cipher.NewCTR(ctr.Block, iv)

	ct := make([]byte, len(pt))
	stream.XORKeyStream(ct, pt)
	return ct
}

func (ctr AESCTRHMAC) tag(nonce, aad, ct []byte) []byte {
	h := hmac.New(ctr.Hash.New, ctr.AuthKey)
	binary.Write(h, binary.BigEndian, uint64(len(aad)))
	binary.Write(h, binary.BigEndian, uint64(len(ct)))
	h.Write(nonce)
	h.Write(aad)
	h.Write(ct)
	return h.Sum(nil)[:ctr.TagSize]
}

func (ctr AESCTRHMAC) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	ciphertext := ctr.crypt(nonce, plaintext)
	tag := ctr.tag(nonce, additionalData, ciphertext)
	return append(ciphertext, tag...)
}

func (ctr AESCTRHMAC) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	cut := len(ciphertext) - ctr.TagSize
	innerCiphertext, tag := ciphertext[:cut], ciphertext[cut:]

	computedTag := ctr.tag(nonce, additionalData, innerCiphertext)
	if !hmac.Equal(computedTag, tag) {
		return nil, fmt.Errorf("Authentication failure")
	}

	plaintext := ctr.crypt(nonce, innerCiphertext)
	return plaintext, nil
}

func makeAESCTRHMAC(hash crypto.Hash, encSize, tagSize int) func(key []byte) cipher.AEAD {
	return func(key []byte) cipher.AEAD {
		return newAESCTRHMAC(key, hash, encSize, tagSize)
	}
}

var (
	AES_CTR_128_HMAC_SHA256_4 = CipherSuite{
		ID:      0x0001,
		Name:    "AES_CTR_128_HMAC_SHA256_4",
		Nk:      16,
		Nn:      12,
		Hash:    crypto.SHA256,
		NewAEAD: makeAESCTRHMAC(crypto.SHA256, 16, 4),
	}
	AES_CTR_128_HMAC_SHA256_8 = CipherSuite{
		ID:      0x0002,
		Name:    "AES_CTR_128_HMAC_SHA256_8",
		Nk:      16,
		Nn:      12,
		Hash:    crypto.SHA256,
		NewAEAD: makeAESCTRHMAC(crypto.SHA256, 16, 8),
	}
	AES_GCM_128_SHA256 = CipherSuite{
		ID:      0x0003,
		Name:    "AES_GCM_128_SHA256",
		Nk:      16,
		Nn:      12,
		Hash:    crypto.SHA256,
		NewAEAD: newGCM,
	}
	AES_GCM_256_SHA512 = CipherSuite{
		ID:      0x0004,
		Name:    "AES_GCM_256_SHA512",
		Nk:      32,
		Nn:      12,
		Hash:    crypto.SHA512,
		NewAEAD: newGCM,
	}
)

func (suite CipherSuite) Extract(ikm, salt []byte) []byte {
	return hkdf.Extract(suite.Hash.New, ikm, salt)
}

func (suite CipherSuite) Expand(prk, info []byte, size int) []byte {
	out := make([]byte, size)
	r := hkdf.Expand(suite.Hash.New, prk, info)
	r.Read(out)
	return out
}

func (suite CipherSuite) MarshalJSON() ([]byte, error) {
	return json.Marshal(suite.ID)
}

///
/// Test vector format
///

type HexData []byte

func (hd HexData) MarshalJSON() ([]byte, error) {
	hs := hex.EncodeToString(hd)
	return json.Marshal(hs)
}

type Encryption struct {
	KID        uint64  `json:"kid"`
	CTR        uint64  `json:"ctr"`
	Header     HexData `json:"header"`
	Nonce      HexData `json:"nonce"`
	Ciphertext HexData `json:"ciphertext"`
}

type TestVector struct {
	CipherSuite CipherSuite  `json:"cipher_suite"`
	BaseKey     HexData      `json:"base_key"`
	Key         HexData      `json:"key"`
	Salt        HexData      `json:"salt"`
	Plaintext   HexData      `json:"plaintext"`
	Encryptions []Encryption `json:"encryptions"`
}

///
/// Test vector generation
///
type HeaderCase struct {
	KID uint64
	CTR uint64
}

type TestCase struct {
	CipherSuite CipherSuite
	BaseKey     []byte
	Plaintext   []byte
	HeaderCases []HeaderCase
}

func minBigEndian(val uint64) []byte {
	max := make([]byte, 8)
	binary.BigEndian.PutUint64(max, val)
	for i, b := range max {
		if b != 0 {
			return max[i:]
		}
	}
	return []byte{0}
}

func makeHeader(headerCase HeaderCase) []byte {
	kidData := minBigEndian(headerCase.KID)
	ctrData := minBigEndian(headerCase.CTR)

	KLEN := byte(len(kidData))
	if KLEN > 8 {
		panic(fmt.Sprintf("KID too long"))
	}

	LEN := byte(len(ctrData))

	if LEN > 8 {
		panic(fmt.Sprintf("CTR too long"))
	}

	config := (LEN - 1) << 4
	if headerCase.KID <= 7 {
		config |= byte(headerCase.KID)
		kidData = nil
		KLEN = 0
	} else {
		config |= 0x08 | (KLEN - 1)
	}

	header := make([]byte, 1+LEN+KLEN)
	header[0] = config
	copy(header[1:1+KLEN], kidData)
	copy(header[1+KLEN:], ctrData)
	return header
}

func encrypt(suite CipherSuite, headerCase HeaderCase, key, salt, plaintext []byte) Encryption {
	header := makeHeader(headerCase)

	nonce := make([]byte, suite.Nn)
	binary.BigEndian.PutUint64(nonce[suite.Nn-8:], headerCase.CTR)
	for i := range nonce {
		nonce[i] ^= salt[i]
	}

	aead := suite.NewAEAD(key)
	ct := aead.Seal(nil, nonce, plaintext, header)
	ct = append(header, ct...)

	return Encryption{
		KID:        headerCase.KID,
		CTR:        headerCase.CTR,
		Header:     header,
		Nonce:      nonce,
		Ciphertext: ct,
	}
}

func makeTestVector(tc TestCase) TestVector {
	suite := tc.CipherSuite
	secret := suite.Extract(tc.BaseKey, []byte("SFrame10"))
	key := suite.Expand(secret, []byte("key"), suite.Nk)
	salt := suite.Expand(secret, []byte("salt"), suite.Nn)

	encryptions := make([]Encryption, len(tc.HeaderCases))
	for i, hc := range tc.HeaderCases {
		encryptions[i] = encrypt(suite, hc, key, salt, tc.Plaintext)
	}

	return TestVector{
		CipherSuite: suite,
		BaseKey:     tc.BaseKey,
		Key:         key,
		Salt:        salt,
		Plaintext:   tc.Plaintext,
		Encryptions: encryptions,
	}
}

///
/// main
///

func fromHex(h string) []byte {
	b, _ := hex.DecodeString(h)
	return b
}

func toHex(b []byte, width, indent int) string {
	h := hex.EncodeToString(b)
	pad := strings.Repeat(" ", indent)

	if len(h) < width {
		return h
	}

	out := h[:width] + "\n"
	start := width
	for start < len(h)-width {
		out += pad + h[start:start+width] + "\n"
		start += width
	}

	if start != len(h) {
		out += pad + h[start:]
	} else {
		out = out[:len(out)-1]
	}

	return out
}

var (
	hexWidth     = 32
	hexIndent    = 16
	testVectorMD = `## %s

~~~
CipherSuite:    0x%02x
Base Key:       %s
Key:            %s
Salt:           %s
Plaintext:      %s
~~~
`

	encryptionMD = `
~~~
KID:            0x%x
CTR:            0x%x
Header:         %s
Nonce:          %s
Ciphertext:     %s
~~~
`
)

func renderMarkdown(tv TestVector) string {
	cipherName := tv.CipherSuite.Name
	cipherID := tv.CipherSuite.ID
	baseKeyMD := toHex(tv.BaseKey, hexWidth, hexIndent)
	keyMD := toHex(tv.Key, hexWidth, hexIndent)
	saltMD := toHex(tv.Salt, hexWidth, hexIndent)
	plaintextMD := toHex(tv.Plaintext, hexWidth, hexIndent)
	out := fmt.Sprintf(testVectorMD, cipherName, cipherID, baseKeyMD, keyMD, saltMD, plaintextMD)

	for _, enc := range tv.Encryptions {
		headerMD := toHex(enc.Header, hexWidth, hexIndent)
		nonceMD := toHex(enc.Nonce, hexWidth, hexIndent)
		ciphertextMD := toHex(enc.Ciphertext, hexWidth, hexIndent)
		out += fmt.Sprintf(encryptionMD, enc.KID, enc.CTR, headerMD, nonceMD, ciphertextMD)
	}

	return out
}

func main() {
	// Test parameters
	plaintext := []byte("From heavenly harmony // This universal frame began")

	headerCases := []HeaderCase{
		HeaderCase{KID: 0x07, CTR: 0x00},
		HeaderCase{KID: 0x07, CTR: 0x01},
		HeaderCase{KID: 0x07, CTR: 0x02},
		HeaderCase{KID: 0x0f, CTR: 0xaa},
		HeaderCase{KID: 0x01ff, CTR: 0xaa},
		HeaderCase{KID: 0x01ff, CTR: 0xaaaa},
		HeaderCase{KID: 0xffffffffffffff, CTR: 0xffffffffffffff},
	}

	testCases := []TestCase{
		TestCase{
			CipherSuite: AES_CTR_128_HMAC_SHA256_4,
			BaseKey:     fromHex("101112131415161718191a1b1c1d1e1f"),
			Plaintext:   plaintext,
			HeaderCases: headerCases,
		},
		TestCase{
			CipherSuite: AES_CTR_128_HMAC_SHA256_8,
			BaseKey:     fromHex("202122232425262728292a2b2c2d2e2f"),
			Plaintext:   plaintext,
			HeaderCases: headerCases,
		},
		TestCase{
			CipherSuite: AES_GCM_128_SHA256,
			BaseKey:     fromHex("303132333435363738393a3b3c3d3e3f"),
			Plaintext:   plaintext,
			HeaderCases: headerCases,
		},
		TestCase{
			CipherSuite: AES_GCM_256_SHA512,
			BaseKey:     fromHex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
			Plaintext:   plaintext,
			HeaderCases: headerCases,
		},
	}

	// Command-line flags
	var jsonFlag, mdFlag bool
	flag.BoolVar(&jsonFlag, "json", false, "Output JSON")
	flag.BoolVar(&mdFlag, "md", false, "Output Markdown")
	flag.Parse()

	if jsonFlag == mdFlag {
		panic("Exactly one output format must be specified")
	}

	// Generate and render test vectors
	testVectors := make([]TestVector, len(testCases))
	for i, tc := range testCases {
		testVectors[i] = makeTestVector(tc)
	}

	if jsonFlag {
		jsonVectors, err := json.MarshalIndent(testVectors, "", "  ")
		chk(err)
		fmt.Println(string(jsonVectors))
	}

	if mdFlag {
		for _, tv := range testVectors {
			fmt.Println(renderMarkdown(tv))
		}
	}
}
