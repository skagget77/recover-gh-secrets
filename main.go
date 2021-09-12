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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const usage = `
NAME
       recover-gh-secrets - Recover Actions Secrets from a GitHub repository

SYNOPSIS
       recover-gh-secrets client [-r <address>[:<port>]] <env>...
       recover-gh-secrets decrypt <key> <data>
       recover-gh-secrets genkey
       recover-gh-secrets server [-t [<address>]] [<port>]

DESCRIPTION
       To recover GitHub Actions Secrets run recover-gh-secrets client as a
       GitHub Action in the repository that contain the Actions Secrets to
       recover.

       recover-gh-secrets client [-r <address>[:<port>]] <env>...
           Encrypt the GitHub Actions Secrets using the AES-256 key specified
           as an environment variable. Specifying -r causes the encrypted
           Actions Secrets to be sent to the remote host. Note that some
           parameters needs to be given as environment variables for safety
           reasons.

       recover-gh-secrets decrypt <key> <data>
           Decrypt the GitHub Actions Secrets encrypted data using the given 
           AES-256 key.

       recover-gh-secrets genkey
           Generate a new random AES-256 key which is used to protect the
           GitHub Actions Secrets.

       recover-gh-secrets server [-t [<address>]] [<port>]
           Run a server receiving encrypted GitHub Actions Secrets from remote
           hosts. The server will listen on all global unicast addresses. The
           default port is 19771. Specifying -t enables TLS. When an IP address
           is given to -t the server certificate will include that IP address
           allowing TLS to work even though the server is behind a router with
           NAT.

ENVIRONMENT
       The following environment variables can be used with the client command:

       RECOVER_GH_SECRETS_CERT
           Server root CA certificate in PEM format. Note that the BEGIN/END
           CERTIFICATE lines must be included. Having this environment variable
           defined enables TLS on the client side.

       RECOVER_GH_SECRETS_KEY
           AES-256 key used to protect the GitHub Actions Secrets. Generate a
           compatible key using the genkey command.

       RECOVER_GH_SECRETS_REMOTE
           Remote host to send the encrypted GitHub Actions Secrets to. The
           client -r command line option override the environment variable.
`

// errParamCount signals that the number of parameters provided on the command
// line is invalid.
var errParamCount = errors.New("invalid number of command line parameters")

// runDecrypt decrypts the data using the given AES-256 key. The decrypted data
// is written to standard output. Both the key and the data should be base64
// encoded.
func runDecrypt(key, data string) error {
	buf := &bytes.Buffer{}
	keyDecoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(key))
	if _, err := io.CopyN(buf, keyDecoder, 32); err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	aesCipher, err := aes.NewCipher(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	buf = &bytes.Buffer{}
	dataDecoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(data))
	if _, err := io.CopyN(buf, dataDecoder, aes.BlockSize); err != nil {
		return fmt.Errorf("failed to decode IV: %w", err)
	}

	envSet := make(map[string]string)
	reader := cipher.StreamReader{S: cipher.NewOFB(aesCipher, buf.Bytes()), R: dataDecoder}
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

// encryptTo encrypts data with the specified AES-256 key. The encrypted data
// is written to the given destination.
func encryptTo(dest io.Writer, key string, data map[string]string) error {
	buf := &bytes.Buffer{}
	keyDecoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(key))
	if _, err := io.CopyN(buf, keyDecoder, 32); err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	aesCipher, err := aes.NewCipher(buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	buf = &bytes.Buffer{}
	if _, err := io.CopyN(buf, rand.Reader, aes.BlockSize); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	dataEncoder := base64.NewEncoder(base64.StdEncoding, dest)
	defer dataEncoder.Close()
	writer := cipher.StreamWriter{S: cipher.NewOFB(aesCipher, buf.Bytes()), W: dataEncoder}
	if _, err := io.CopyN(dataEncoder, buf, aes.BlockSize); err != nil {
		return fmt.Errorf("failed to encode IV: %w", err)
	}
	if err := json.NewEncoder(writer).Encode(&data); err != nil {
		return fmt.Errorf("failed to encode JSON data: %w", err)
	}

	return nil
}

// lookupEnvs returns a map with a name/value pair for each of the environment
// variables specified.
func lookupEnvs(envs []string) map[string]string {
	envSet := make(map[string]string)
	for _, env := range envs {
		envSet[env] = ""
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

// runLocalClient runs a client that writes the specified encrypted environment
// variables to standard output.
func runLocalClient(key string, envs []string) error {
	if err := encryptTo(os.Stdout, key, lookupEnvs(envs)); err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	fmt.Println()
	return nil
}

// runRemoteClient runs a client that writes the specified encrypted
// environment variables to a remote server.
func runRemoteClient(key string, envs []string, address string) error {
	buf := &bytes.Buffer{}
	if err := encryptTo(buf, key, lookupEnvs(envs)); err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port, err = net.SplitHostPort(address + ":19771")
		if err != nil {
			return err
		}
	}

	client := http.DefaultClient
	res, err := client.Post(fmt.Sprintf("http://%s:%s", host, port), "text/plain", buf)
	if err != nil {
		return fmt.Errorf("failed to post data: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("response status: %s", res.Status)
	}

	return nil
}

// parseRoot parses the specified buffer for PEM encoded root certificates. All
// root certificates found are added to the returned certificate pool.
func parseRoot(buf []byte) (*x509.CertPool, error) {
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

// runRemoteClientTLS runs a client that writes the specified encrypted
// environment variables to a remote server. The connection to the remote
// server is protected with TLS.
func runRemoteClientTLS(key string, envs []string, address, cert string) error {
	buf := &bytes.Buffer{}
	if err := encryptTo(buf, key, lookupEnvs(envs)); err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	certPool, err := parseRoot([]byte(cert))
	if err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: certPool}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port, err = net.SplitHostPort(address + ":19771")
		if err != nil {
			return err
		}
	}

	client := &http.Client{Transport: transport}
	res, err := client.Post(fmt.Sprintf("https://%s:%s", host, port), "text/plain", buf)
	if err != nil {
		return fmt.Errorf("failed to post data: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return fmt.Errorf("response status: %s", res.Status)
	}

	return nil
}

// lookupHostIP returns all global unicast IP addresses for the host.
func lookupHostIP() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate network interfaces: %w", err)
	}

	var ips []net.IP
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, fmt.Errorf("failed to parse CIDR address: %w", err)
		}

		if ip.IsGlobalUnicast() {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("failed to find any global unicast addresses")
	}

	return ips, nil
}

// createRoot returns a new DER encoded root certificate and the private key
// used to sign descendant certificates. The root certficate is valid for 48
// hours.
func createRoot() ([]byte, ed25519.PrivateKey, error) {
	pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	name := pkix.Name{
		Country:      []string{"SE"},
		Locality:     []string{"Stockholm"},
		Organization: []string{"Secrets Recovery Inc"},
		CommonName:   "Recover GH Secrets CA",
	}

	// Valid for 48 hours
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Issuer:                name,
		Subject:               name,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	buf, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, prvKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate from template: %w", err)
	}

	return buf, prvKey, nil
}

// createCert returns a new DER encoded certificate tied to the specified IP
// addresses and signed by the given root certificate. The certificate is valid
// for 24 hours.
func createCert(ca []byte, caKey ed25519.PrivateKey, globalIPs []net.IP) ([]byte, ed25519.PrivateKey, error) {
	caCert, err := x509.ParseCertificate(ca)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	pubKey, prvKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	name := pkix.Name{
		Country:      []string{"SE"},
		Locality:     []string{"Stockholm"},
		Organization: []string{"Secrets Recovery Inc"},
		CommonName:   "Recover GH Secrets Server",
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Issuer:       caCert.Subject,
		Subject:      name,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  globalIPs,
	}

	buf, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pubKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate from template: %w", err)
	}

	return buf, prvKey, nil
}

// serverHandler writes the body of the request to standard output.
func serverHandler(w http.ResponseWriter, r *http.Request) {
	if _, err := io.Copy(os.Stdout, io.MultiReader(r.Body, strings.NewReader("\n"))); err != nil {
		fmt.Println(err)
	}

	w.WriteHeader(http.StatusOK)
}

// runServer runs a server reading encrypted environment variables from
// a remote host on the specified port.
func runServer(port int) error {
	globalIPs, err := lookupHostIP()
	if err != nil {
		return err
	}

	var addrs []string
	for _, ip := range globalIPs {
		addrs = append(addrs, fmt.Sprintf("%s:%d", ip, port))
	}
	fmt.Printf("The server is listening on: %s\n", strings.Join(addrs, ", "))
	fmt.Printf("Running with TLS disabled.\n\n")

	server := http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      http.HandlerFunc(serverHandler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return server.ListenAndServe()
}

// runServerTLS runs a server reading encrypted environment variables from
// a remote host on the specified port. The connection is protected by TLS.
// Address can be used to specify an additional IP address to include in the
// server certificate, e.g. when the server runs behind a router with NAT.
func runServerTLS(port int, address net.IP) error {
	root, rootKey, err := createRoot()
	if err != nil {
		return fmt.Errorf("failed to create root CA certificate: %w", err)
	}

	rootPEM := &strings.Builder{}
	err = pem.Encode(rootPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: root,
	})
	if err != nil {
		return fmt.Errorf("failed to PEM encode root CA certificate: %w", err)
	}

	globalIPs, err := lookupHostIP()
	if err != nil {
		return fmt.Errorf("failed to lookup host IP: %w", err)
	}
	var addrs []string
	for _, ip := range globalIPs {
		addrs = append(addrs, fmt.Sprintf("%s:%d", ip, port))
	}

	if address != nil {
		globalIPs = append(globalIPs, address)
	}
	cert, key, err := createCert(root, rootKey, globalIPs)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	fmt.Printf("The server is listening on: %s\n", strings.Join(addrs, ", "))
	fmt.Printf("Running with TLS enabled. Set RECOVER_GH_SECRETS_CERT to the following CA\n")
	fmt.Printf("certificate on the client side:\n")
	fmt.Printf("\n%s\n", rootPEM)
	fmt.Printf("The certificate is valid for 24 hours. After that time you need to restart\n")
	fmt.Printf("the server to issue new certificates\n\n")

	server := http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      http.HandlerFunc(serverHandler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{cert, root},
				PrivateKey:  key,
			}},
		},
	}

	return server.ListenAndServeTLS("", "")
}

// parseCmdServer parses the arguments given to the server command when the -t
// flag is given.
func parseCmdServer(cmdFlag *flag.FlagSet) (int, net.IP, error) {
	switch cmdFlag.NArg() {
	case 0:
		return 19771, nil, nil
	case 1:
		addr := net.ParseIP(cmdFlag.Arg(0))
		if addr != nil {
			return 19771, addr, nil
		}
		port, err := strconv.Atoi(cmdFlag.Arg(0))
		if err == nil {
			return port, nil, nil
		}
		return 0, nil, fmt.Errorf("invalid IP address or port number")
	case 2:
		addr := net.ParseIP(cmdFlag.Arg(0))
		if addr == nil {
			return 0, nil, fmt.Errorf("invalid IP address")
		}
		port, err := strconv.Atoi(cmdFlag.Arg(1))
		if err != nil {
			return 0, nil, fmt.Errorf("invalid port number")
		}
		return port, addr, nil
	default:
		return 0, nil, errParamCount
	}
}

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	cmdFlag := flag.NewFlagSet("recover-gh-secrets", flag.ExitOnError)
	cmdFlag.Usage = func() {
		fmt.Println(usage)
	}

	var err error
	switch cmd {
	case "client":
		r := cmdFlag.String("r", "", "")
		cmdFlag.Parse(os.Args[2:])
		if *r == "" {
			*r = os.Getenv("RECOVER_GH_SECRETS_REMOTE")
		}

		if len(cmdFlag.Args()) > 0 {
			crt := os.Getenv("RECOVER_GH_SECRETS_CERT")
			key := os.Getenv("RECOVER_GH_SECRETS_KEY")
			switch {
			case *r == "":
				err = runLocalClient(key, cmdFlag.Args())
			case crt == "":
				err = runRemoteClient(key, cmdFlag.Args(), *r)
			default:
				err = runRemoteClientTLS(key, cmdFlag.Args(), *r, crt)
			}
		} else {
			err = errParamCount
		}
	case "decrypt":
		cmdFlag.Parse(os.Args[2:])
		if cmdFlag.NArg() == 2 {
			err = runDecrypt(cmdFlag.Arg(0), cmdFlag.Arg(1))
		} else {
			err = errParamCount
		}
	case "genkey":
		cmdFlag.Parse(os.Args[2:])
		if cmdFlag.NArg() == 0 {
			err = runGenerateKey()
		} else {
			err = errParamCount
		}
	case "server":
		t := cmdFlag.Bool("t", false, "")
		cmdFlag.Parse(os.Args[2:])

		if err == nil {
			if *t {
				var port int
				var address net.IP
				port, address, err = parseCmdServer(cmdFlag)
				if err == nil {
					err = runServerTLS(port, address)
				}
			} else {
				port := 19771
				if cmdFlag.NArg() == 1 {
					port, err = strconv.Atoi(cmdFlag.Arg(0))
				} else if cmdFlag.NArg() > 1 {
					err = errParamCount
				}
				if err == nil {
					err = runServer(port)
				}
			}
		}
	case "help", "", "-h", "-help", "--help":
		cmdFlag.Usage()
	default:
		err = fmt.Errorf("invalid command: %s", cmd)
	}

	if err != nil {
		fmt.Println(err)
		cmdFlag.Usage()
		os.Exit(1)
	}
}
