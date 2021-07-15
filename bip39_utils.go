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
	"errors"
	"fmt"
	"sort"
	"strconv"
)

var (
	ErrBinaryString = errors.New("The specified binary string is not valid")
)

// Convert the specified byte slice to a binary string.
func bytesToBinaryString(slice []byte) string {
	var strBuff bytes.Buffer
	for _, b := range slice {
		strBuff.WriteString(fmt.Sprintf("%.8b", b))
	}

	return strBuff.String()
}

// Convert the specified binary string to a byte slice.
func binaryStringToBytes(binStr string) ([]byte, error) {
	if (len(binStr) % 8) != 0 {
		return nil, ErrBinaryString
	}

	slice := make([]byte, 0, len(binStr)/8)

	for i := 0; i < len(binStr); i += 8 {
		byteStrBin := binStr[i : i+8]
		byteVal, err := strconv.ParseInt(byteStrBin, 2, 16)
		if err != nil {
			return nil, err
		}
		slice = append(slice, byte(byteVal))
	}

	return slice, nil
}

// Perform binary search to find a string in a slice, by returning its index.
// If not found, -1 will be returned.
// The algorithm is simply implemented by using the sort library.
func stringBinarySearch(slice []string, elem string) int {
	idx := sort.SearchStrings(slice, elem)

	if idx != len(slice) && slice[idx] == elem {
		return idx
	} else {
		return -1
	}
}
