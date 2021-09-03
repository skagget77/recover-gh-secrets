// Copyright (c) 2021 Johan Andersson <skagget77@gmail.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const usage = `
NAME
       recover-gh-secrets - Recover Actions Secrets from a GitHub repository

SYNOPSIS
       recover-gh-secrets -g
       recover-gh-secrets -d <key> <data>
       recover-gh-secrets -s [<host>][:<port>]
       recover-gh-secrets [-r <host>[:<port>]] <key> <env>...

DESCRIPTION
       To recover GitHub Actions Secrets run recover-gh-secrets as a GitHub
       Action in the repository that contain the Actions Secrets to recover.

       recover-gh-secrets -g
           Generate a new random AES-256 key which is used to protect the
           GitHub Actions Secrets.

       recover-gh-secrets -d <key> <data>
           Decrypt the GitHub Actions Secrets encrypted data using the given 
           AES-256 key.

       recover-gh-secrets -s [<address>][:<port>]
           Run a server reading encrypted GitHub Actions Secrets from the given
           address and port.

       recover-gh-secrets [-r <address>[:<port>]] <key> <secret>...
           Encrypt the specified GitHub Actions Secrets using the given AES-256
           key. Specifying -r causes the encrypted Actions Secrets to be sent
           to the remote address.

ENVIRONMENT
       The following environment variables can be used to enabled TLS when
	   running a client/server setup.

       RECOVER_GH_SECRETS_CRTFILE
           Path to certificate file in PEM format. The file should contain both
		   the CA and the certificate signed by the CA. Used by both the client
		   and the server.

       RECOVER_GH_SECRETS_KEYFILE
           Path to certificate key in PEM format. Used by the server.
`

// errParamCount signals that the number of parameters provided on the command
// line is invalid.
var errParamCount = errors.New("invalid number of parameters")

// lookupEnvs returns a map with a name/value pair for each of the environment
// variable specified.
func lookupEnvs(names ...string) map[string]string {
	envSet := make(map[string]string)
	for _, name := range names {
		envSet[name] = ""
	}

	for _, env := range os.Environ() {
		i := strings.Index(env, "=")
		if i == -1 {
			continue
		}

		if _, ok := envSet[env[:i]]; ok {
			envSet[env[:i]] = env[i+1:]
		}
	}

	return envSet
}

// encryptTo encrypts data with the specified AES-256 key. The encrypted data
// is written to the given destination.
func encryptTo(dest io.Writer, aesKey string, data map[string]string) error {
	key := &bytes.Buffer{}
	keyDecoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(aesKey))
	if _, err := io.CopyN(key, keyDecoder, 32); err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	aesCipher, err := aes.NewCipher(key.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	iv := &bytes.Buffer{}
	if _, err := io.CopyN(iv, rand.Reader, aes.BlockSize); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	dataEncoder := base64.NewEncoder(base64.StdEncoding, dest)
	defer dataEncoder.Close()
	writer := cipher.StreamWriter{S: cipher.NewOFB(aesCipher, iv.Bytes()), W: dataEncoder}
	if _, err := io.CopyN(dataEncoder, iv, aes.BlockSize); err != nil {
		return fmt.Errorf("failed to encode IV: %w", err)
	}
	if err := json.NewEncoder(writer).Encode(&data); err != nil {
		return fmt.Errorf("failed to encode JSON data: %w", err)
	}

	return nil
}

// runDecrypt decrypts the data using the given AES-256 key. The decrypted data
// is written to standard output. Both the key and the data should be base64
// encoded.
func runDecrypt(aesKey, data string) error {
	key := &bytes.Buffer{}
	keyDecoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(aesKey))
	if _, err := io.CopyN(key, keyDecoder, 32); err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	aesCipher, err := aes.NewCipher(key.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	iv := &bytes.Buffer{}
	dataDecoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))
	if _, err := io.CopyN(iv, dataDecoder, aes.BlockSize); err != nil {
		return fmt.Errorf("failed to decode IV: %w", err)
	}

	envSet := make(map[string]string)
	reader := cipher.StreamReader{S: cipher.NewOFB(aesCipher, iv.Bytes()), R: dataDecoder}
	if err := json.NewDecoder(reader).Decode(&envSet); err != nil {
		return fmt.Errorf("failed to decode JSON data: %w", err)
	}

	for name, value := range envSet {
		fmt.Printf("%s=%q\n", name, value)
	}

	return nil
}

// runGenerateKey writes a new random base64 encoded AES-256 key to standard
// output.
func runGenerateKey() error {
	coder := base64.NewEncoder(base64.StdEncoding, os.Stdout)
	if _, err := io.CopyN(coder, rand.Reader, 32); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	coder.Close()

	fmt.Println()
	return nil
}

// runLocalClient runs a client that writes the specified encrypted environment
// variables to standard output.
func runLocalClient(aesKey string, names ...string) error {
	if err := encryptTo(os.Stdout, aesKey, lookupEnvs(names...)); err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	fmt.Println()
	return nil
}

// parseCACerts parses the specified buffer for CA certificates. All CA
// certificates found are added to the certificate pool returned.
func parseCACerts(buf []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	for {
		var block *pem.Block
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		if cert.IsCA {
			certPool.AddCert(cert)
		}
	}

	return certPool, nil
}

// runRemoteClient runs a client that writes the specified encrypted environment
// variables to a remote server.
func runRemoteClient(address, aesKey string, names ...string) error {
	crtFile := os.Getenv("RECOVER_GH_SECRETS_CRTFILE")

	client := http.DefaultClient
	scheme := "http"
	if crtFile != "" {
		buf, err := os.ReadFile(crtFile)
		if err != nil {
			return fmt.Errorf("failed to read certificate file: %w", err)
		}

		certPool, err := parseCACerts(buf)
		if err != nil {
			return err
		}

		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: certPool}

		client = &http.Client{Transport: transport}
		scheme = "https"
	}

	buf := &bytes.Buffer{}
	if err := encryptTo(buf, aesKey, lookupEnvs(names...)); err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	res, err := client.Post(fmt.Sprintf("%s://%s", scheme, address), "text/plain", buf)
	if err != nil {
		return fmt.Errorf("failed to post data: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("response status: %s", res.Status)
	}

	return nil
}

// runServer runs a server reading encrypted environment variables from
// specified address and port. The read environment variables are written to
// the standard output.
func runServer(address string) error {
	crtFile := os.Getenv("RECOVER_GH_SECRETS_CRTFILE")
	keyFile := os.Getenv("RECOVER_GH_SECRETS_KEYFILE")

	handler := func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(log.Writer(), io.MultiReader(r.Body, strings.NewReader("\n"))); err != nil {
			log.Println(err)
		}

		w.WriteHeader(http.StatusOK)
	}

	server := http.Server{
		Addr:         address,
		Handler:      http.HandlerFunc(handler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if crtFile != "" && keyFile != "" {
		return server.ListenAndServeTLS(crtFile, keyFile)
	}

	return server.ListenAndServe()
}

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Println(usage)
		os.Exit(1)
	}

	d := flag.Bool("d", false, "")
	g := flag.Bool("g", false, "")
	s := flag.Bool("s", false, "")
	r := flag.String("r", "", "")
	flag.Parse()

	var err error
	switch {
	case *d:
		if flag.NArg() == 2 {
			err = runDecrypt(flag.Arg(0), flag.Arg(1))
		} else {
			err = errParamCount
		}
	case *g:
		if flag.NArg() == 0 {
			err = runGenerateKey()
		} else {
			err = errParamCount
		}
	case *s:
		if flag.NArg() == 1 {
			err = runServer(flag.Arg(0))
		} else {
			err = errParamCount
		}
	case *r != "":
		if flag.NArg() > 1 {
			err = runRemoteClient(*r, flag.Arg(0), flag.Args()[1:]...)
		} else {
			err = errParamCount
		}
	default:
		if flag.NArg() > 1 {
			err = runLocalClient(flag.Arg(0), flag.Args()[1:]...)
		} else {
			err = errParamCount
		}
	}
	if err != nil {
		log.Printf("error: %s\n", err)
		//flag.Usage()
	}
}
