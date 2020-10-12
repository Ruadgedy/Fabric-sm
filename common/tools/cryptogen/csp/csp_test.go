/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package csp_test

import (
	"encoding/hex"
	"errors"
	"github.com/flyinox/crypto/sm/sm2"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/tools/cryptogen/csp"
	"github.com/stretchr/testify/assert"
)

// mock implementation of bccsp.Key interface
type mockKey struct {
	pubKeyErr error
	bytesErr  error
	pubKey    bccsp.Key
}

func (mk *mockKey) Bytes() ([]byte, error) {
	if mk.bytesErr != nil {
		return nil, mk.bytesErr
	}
	return []byte{1, 2, 3, 4}, nil
}

func (mk *mockKey) PublicKey() (bccsp.Key, error) {
	if mk.pubKeyErr != nil {
		return nil, mk.pubKeyErr
	}
	return mk.pubKey, nil
}

func (mk *mockKey) SKI() []byte { return []byte{1, 2, 3, 4} }

func (mk *mockKey) Symmetric() bool { return false }

func (mk *mockKey) Private() bool { return false }

var testDir = filepath.Join(os.TempDir(), "csp-test")

func TestLoadPrivateKey(t *testing.T) {
	// 生成私钥
	priv, _, _ := csp.GeneratePrivateKey(testDir,"sm2","")
	pkFile := filepath.Join(testDir, hex.EncodeToString(priv.SKI())+"_sk")
	assert.Equal(t, true, checkForFile(pkFile),
		"Expected to find private key file")
	loadedPriv, _, _ := csp.LoadPrivateKey(testDir)
	assert.NotNil(t, loadedPriv, "Should have returned a bccsp.Key")
	assert.Equal(t, priv.SKI(), loadedPriv.SKI(), "Should have same subject identifier")
	cleanup(testDir)
}

func TestLoadPrivateKey_wrongEncoding(t *testing.T) {
	if err := os.Mkdir(testDir, 0755); err != nil {
		panic("failed to create dir " + testDir + ":" + err.Error())
	}
	filename := testDir + "/wrong_encoding_sk"
	file, err := os.Create(filename)
	if err != nil {
		panic("failed to create tmpfile " + filename + ":" + err.Error())
	}
	defer file.Close()
	_, err = file.Write([]byte("wrong_encoding"))
	if err != nil {
		panic("failed to write to " + filename + ":" + err.Error())
	}
	file.Close() // To flush test file content
	_, _, err = csp.LoadPrivateKey(testDir)
	assert.NotNil(t, err)
	assert.EqualError(t, err, testDir+"/wrong_encoding_sk: wrong PEM encoding")
	cleanup(testDir)
}

func TestGeneratePrivateKey(t *testing.T) {

	priv, signer, err := csp.GeneratePrivateKey(testDir,"sm2","")
	assert.NoError(t, err, "Failed to generate private key")
	assert.NotNil(t, priv, "Should have returned a bccsp.Key")
	assert.Equal(t, true, priv.Private(), "Failed to return private key")
	assert.NotNil(t, signer, "Should have returned a crypto.Signer")
	pkFile := filepath.Join(testDir, hex.EncodeToString(priv.SKI())+"_sk")
	t.Log(pkFile)
	assert.Equal(t, true, checkForFile(pkFile),
		"Expected to find private key file")
	//cleanup(testDir)

}

func TestGetECPublicKey(t *testing.T) {

	priv, _, err := csp.GeneratePrivateKey(testDir,"sm2","")
	assert.NoError(t, err, "Failed to generate private key")

	ecPubKey, err := csp.GetECPublicKey(priv)
	assert.NoError(t, err, "Failed to get public key from private key")
	//assert.IsType(t, &ecdsa.PublicKey{}, ecPubKey,
	//	"Failed to return an ecdsa.PublicKey")

	// 修改的测试sm2公钥类型
	assert.IsType(t, &sm2.PublicKey{}, ecPubKey, "Failed to return an sm2.PublicKey")
	// force errors using mockKey
	priv = &mockKey{
		pubKeyErr: nil,
		bytesErr:  nil,
		pubKey:    &mockKey{},
	}
	_, err = csp.GetECPublicKey(priv)
	assert.Error(t, err, "Expected an error with a invalid pubKey bytes")
	priv = &mockKey{
		pubKeyErr: nil,
		bytesErr:  nil,
		pubKey: &mockKey{
			bytesErr: errors.New("bytesErr"),
		},
	}
	_, err = csp.GetECPublicKey(priv)
	assert.EqualError(t, err, "bytesErr", "Expected bytesErr")
	priv = &mockKey{
		pubKeyErr: errors.New("pubKeyErr"),
		bytesErr:  nil,
		pubKey:    &mockKey{},
	}
	_, err = csp.GetECPublicKey(priv)
	assert.EqualError(t, err, "pubKeyErr", "Expected pubKeyErr")

	//cleanup(testDir)
}

func cleanup(dir string) {
	os.RemoveAll(dir)
}

func checkForFile(file string) bool {
	/*
	golang判断文件或文件夹是否存在的方法为使用os.Stat()函数返回的错误值进行判断:

	如果返回的错误为nil,说明文件或文件夹存在
	如果返回的错误类型使用os.IsNotExist()判断为true,说明文件或文件夹不存在
	如果返回的错误为其它类型,则不确定是否在存在
	*/
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}

func TestTempDir(t *testing.T)  {
	println(os.TempDir())
}
