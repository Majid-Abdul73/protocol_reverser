package obfuscator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
)

// Obfuscator handles packet obfuscation
type Obfuscator struct {
	key []byte
	iv  []byte
}

// NewObfuscator creates a new obfuscator with random key and IV
func NewObfuscator() (*Obfuscator, error) {
	key := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return &Obfuscator{
		key: key,
		iv:  iv,
	}, nil
}

// ObfuscatePayload applies various obfuscation techniques to the payload
func (o *Obfuscator) ObfuscatePayload(payload []byte) ([]byte, error) {
	// First, encrypt the payload
	encrypted, err := o.encryptPayload(payload)
	if err != nil {
		return nil, err
	}

	// Add jitter data
	jittered := o.addJitterData(encrypted)

	// Split into smaller chunks
	chunks := o.splitIntoChunks(jittered, 128)

	// Reassemble with markers
	return o.assembleWithMarkers(chunks), nil
}

func (o *Obfuscator) encryptPayload(payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(o.key)
	if err != nil {
		return nil, err
	}

	// Create CBC mode encrypter
	mode := cipher.NewCBCEncrypter(block, o.iv)

	// Pad payload to block size
	padded := o.pkcs7Padding(payload, aes.BlockSize)

	// Encrypt payload
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)

	return encrypted, nil
}

func (o *Obfuscator) addJitterData(data []byte) []byte {
	// Add random jitter data between chunks
	result := make([]byte, 0, len(data)+32)

	// Add random prefix
	jitter := make([]byte, 16)
	io.ReadFull(rand.Reader, jitter)
	result = append(result, jitter...)

	// Add data
	result = append(result, data...)

	// Add random suffix
	io.ReadFull(rand.Reader, jitter)
	result = append(result, jitter...)

	return result
}

func (o *Obfuscator) splitIntoChunks(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

func (o *Obfuscator) assembleWithMarkers(chunks [][]byte) []byte {
	// Add markers between chunks for reassembly
	result := make([]byte, 0)
	marker := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	for i, chunk := range chunks {
		// Add chunk length
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(chunk)))
		result = append(result, length...)

		// Add chunk
		result = append(result, chunk...)

		// Add marker except for last chunk
		if i < len(chunks)-1 {
			result = append(result, marker...)
		}
	}

	return result
}

func (o *Obfuscator) pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}
