// Copyright (c) 2020 Emanuele Bellocchia
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package bip39

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strconv"
	"strings"
)

const (
	WordsNum12 = 12
	WordsNum15 = 15
	WordsNum18 = 18
	WordsNum21 = 21
	WordsNum24 = 24

	wordBitLen = 11

	seedSaltMod      = "mnemonic"
	seedPbkdf2KeyLen = 64
	seedPbkdf2Round  = 2048
)

var (
	ErrWordsNum    = errors.New("The specified words number is not valid for mnemonic generation")
	ErrInvalidWord = errors.New("The mnemonic contains an invalid word")
	ErrChecksum    = errors.New("The checksum of the mnemonic is not valid")

	wordsNumMap = map[int]bool{
		WordsNum12: true,
		WordsNum15: true,
		WordsNum18: true,
		WordsNum21: true,
		WordsNum24: true,
	}
)

// Structure for mnemonic
type Mnemonic struct {
	Words string
}

// Generate mnemonic from the specified words number.
// A random entropy is used for generating mnemonic.
func MnemonicFromWordsNum(wordsNum int) (*Mnemonic, error) {
	err := validateWordsNum(wordsNum)
	if err != nil {
		return nil, err
	}

	entropyBitLen := (wordsNum * 11) - (wordsNum / 3)
	entropy, _ := GenerateEntropy(entropyBitLen)

	return MnemonicFromEntropy(entropy)
}

// Generate mnemonic from the specific entropy.
// The entropy slice shall be of a valid length.
func MnemonicFromEntropy(entropy []byte) (*Mnemonic, error) {
	err := validateEntropyBitLen(len(entropy) * 8)
	if err != nil {
		return nil, err
	}

	entropyBinStr := bytesToBinaryString(entropy)
	chksumBinStr := entropyChecksumBinStr(entropy)
	mnemonicBinStr := entropyBinStr + chksumBinStr

	mnemonicLen := len(mnemonicBinStr) / wordBitLen
	mnemonic := make([]string, 0, mnemonicLen)

	for i := 0; i < mnemonicLen; i++ {
		wordStrBin := mnemonicBinStr[i*wordBitLen : (i+1)*wordBitLen]
		wordIdx, _ := strconv.ParseInt(wordStrBin, 2, 16)
		mnemonic = append(mnemonic, wordsListEn[wordIdx])
	}

	return &Mnemonic{
		Words: strings.Join(mnemonic, " "),
	}, nil
}

// Create mnemonic object from a mnemonic string.
func MnemonicFromString(mnemonic string) *Mnemonic {
	return &Mnemonic{
		Words: mnemonic,
	}
}

// Convert a mnemonic back to entropy bytes.
// Error is returned if mnemonic or checksum is not valid.
func (mnemonic *Mnemonic) ToEntropy() ([]byte, error) {
	entropyBinStr, chksumBinStr, err := mnemonic.getBinaryStrings()
	if err != nil {
		return nil, err
	}

	entropy, _ := binaryStringToBytes(entropyBinStr)
	chksumComp := entropyChecksumBinStr(entropy)

	if chksumComp != chksumBinStr {
		return nil, ErrChecksum
	}

	return entropy, nil
}

// Validate a mnemonic.
// For being valid, all the mnemonic words shall exists in the words list and the checksum shall be valid.
func (mnemonic *Mnemonic) Validate() error {
	entropyBinStr, chksumBinStr, err := mnemonic.getBinaryStrings()
	if err != nil {
		return err
	}

	entropy, _ := binaryStringToBytes(entropyBinStr)
	chksumComp := entropyChecksumBinStr(entropy)

	if chksumComp != chksumBinStr {
		return ErrChecksum
	}

	return nil
}

// Get if a mnemonic is valid.
// It's the same of the Validate method but returns bool instead of error.
func (mnemonic *Mnemonic) IsValid() bool {
	return mnemonic.Validate() == nil
}

// Generate the seed from a mnemonic using the specified passphrase for protection.
func (mnemonic *Mnemonic) GenerateSeed(passphrase string) ([]byte, error) {
	err := mnemonic.Validate()
	if err != nil {
		return nil, err
	}

	salt := seedSaltMod + passphrase
	return pbkdf2.Key([]byte(mnemonic.Words), []byte(salt), seedPbkdf2Round, seedPbkdf2KeyLen, sha512.New), nil
}

// Validate the specified words number.
func validateWordsNum(wordsNum int) error {
	if !wordsNumMap[wordsNum] {
		return ErrWordsNum
	}
	return nil
}

// Compute checksum of the specified entropy bytes, returned as a binary string.
func entropyChecksumBinStr(slice []byte) string {
	hash := sha256.Sum256(slice)
	hashStr := bytesToBinaryString(hash[:])
	chksumBitLen := len(slice) / 4
	return hashStr[:chksumBitLen]
}

// Get the binary strings back from a mnemonic.
// The function returns both entropy and checksum parts.
func (mnemonic *Mnemonic) getBinaryStrings() (string, string, error) {
	wordsList := strings.Split(mnemonic.Words, " ")
	err := validateWordsNum(len(wordsList))
	if err != nil {
		return "", "", err
	}

	var strBuf bytes.Buffer
	for _, word := range wordsList {
		wordIdx := stringBinarySearch(wordsListEn, word)
		if wordIdx == -1 {
			return "", "", ErrInvalidWord
		}
		strBuf.WriteString(fmt.Sprintf("%.11b", wordIdx))
	}

	mnemonicBinStr := strBuf.String()
	chksumLen := len(mnemonicBinStr) / 33
	chksumIdx := len(mnemonicBinStr) - chksumLen

	return mnemonicBinStr[:chksumIdx], mnemonicBinStr[chksumIdx:], nil
}
