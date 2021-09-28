package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/eggsampler/acme/v3"
	"github.com/kevinburke/ssh_config"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/xerrors"
	"io"
	"io/fs"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
)

type Putter interface {
	Put(filename, content string, perm fs.FileMode) error
}
type localFs struct {}

func (l *localFs) Put(filename, content string, perm fs.FileMode) error {
	return ioutil.WriteFile(filename, []byte(content), perm)
}

type remoteFs struct {
	host string
}

func (r *remoteFs) Put(filename, content string, perm fs.FileMode) error {
	//@todo maybe add unencrypted key
	sock, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: os.Getenv("SSH_AUTH_SOCK"),
		Net:  "unix",
	})
	if err != nil {
		return xerrors.Errorf("agent sock: %w", err)
	}
	defer sock.Close()
	sshAgent := agent.NewClient(sock)

	userName := func() string {
		sshUser := ssh_config.Get(r.host, "User")
		if len(sshUser) != 0 {
			return sshUser
		}

		curUser, err := user.Current()
		if err != nil {
			panic(err)
		}
		return curUser.Username
	}()

	conf := &ssh.ClientConfig{
		User:            userName,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(sshAgent.Signers)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	port := "22"
	if sshPort := ssh_config.Get(r.host, "Port"); len(sshPort) != 0 {
		port = sshPort
	}
	host := r.host
	if sshHost := ssh_config.Get(r.host, "Hostname"); len(sshHost) != 0 {
		host = sshHost
	}
	conn, err := ssh.Dial("tcp", host+":"+port, conf)
	if err != nil {
		return xerrors.Errorf("ssh dial: %w", err)
	}
	defer conn.Close()

	sftpClient, err := sftp.NewClient(conn)
	if err != nil {
		return xerrors.Errorf("sfp client: %w", err)
	}

	err = sftpClient.MkdirAll(path.Dir(filename))
	fmt.Printf("sftpClient.MkdirAll(path.Dir(%s)) = %T %v\n", filename, err, err)
	if err != nil {
		//panic(err)
	}
	fDst, err := sftpClient.Create(filename)
	if err != nil {
		return xerrors.Errorf("sftp create: %w", err)
	}
	_, err = io.Copy(fDst, strings.NewReader(content))
	if err != nil {
		return xerrors.Errorf("sftp copy: %w", err)
	}
	fi, err := fDst.Stat()
	if err != nil {
		return xerrors.Errorf("sftp stat: %w", err)
	}
	err = fDst.Chmod(perm)
	fmt.Printf("fDst.Chmod(%v|0444) = %T %v\n", fi.Mode(), err, err)
	if err != nil {
		//panic(err)
	}
	err = fDst.Close()
	fmt.Printf("fDst.Close() = %T %v\n", err, err)
	return nil
}

func main() {
	configPath, domain := os.Args[1], os.Args[2]
	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		panic(err)
	}
	var config struct{
		Accounts map[string]string `json:"accounts"`
		Domains map[string]struct {
			Account string `json:"account"`
			Remote  string `json:"remote"`
			TokenDir string `json:"token_dir"`
			Webroot  string `json:"webroot"`
			Private  string `json:"private"`
			Cert     string `json:"cert"`
		} `json:"domains"`
	}
	err = json.Unmarshal(b, &config)
	if err != nil {
		panic(err)
	}
	domainConfig, ok := config.Domains[domain]
	if !ok {
		panic("no domain:"+domain)
	}

	client, err := acme.NewClient(acme.LetsEncryptProduction)
	if err != nil {
		panic(err)
	}

	keyStr, err := ioutil.ReadFile(config.Accounts[domainConfig.Account])
	if err != nil {
		if !path.IsAbs(config.Accounts[domainConfig.Account]) {
			keyStr, err = ioutil.ReadFile(path.Join(path.Dir(configPath), config.Accounts[domainConfig.Account]))
		}
		if err != nil {
			panic(fmt.Errorf("could no read account pk: %w", err))
		}
	}

	keyDer, _ := pem.Decode(keyStr)
	pk, err := x509.ParsePKCS8PrivateKey(keyDer.Bytes)
	if err != nil {
		panic(err)
	}
	privateKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		panic("")
	}

	account, err := client.NewAccount(privateKey, true, true)
	if err != nil {
		panic(err)
	}
	order, err := client.NewOrderDomains(account, domain)
	if err != nil {
		panic(err)
	}


	var myFs Putter = &localFs{}
	if len(domainConfig.Remote) != 0 {
		myFs = &remoteFs{domainConfig.Remote}
	}
	for _, authURL := range order.Authorizations {
		auth, err := client.FetchAuthorization(account, authURL)
		if err != nil {
			panic(err)
		}

		if auth.Status == "valid" {
			continue
		}

		chal, ok := auth.ChallengeMap[acme.ChallengeTypeHTTP01]
		if !ok {
			panic(err)
		}

		tokenDir := func () string {
			if len(domainConfig.TokenDir) != 0 {
				return domainConfig.TokenDir
			}
			return filepath.Join(domainConfig.Webroot, ".well-known", "acme-challenge")
		}()

		err = myFs.Put(filepath.Join(tokenDir, chal.Token), chal.KeyAuthorization, 0666)
		if err != nil {
			panic(err)
		}

		chal, err = client.UpdateChallenge(account, chal)
		if err != nil {
			panic(err)
		}
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	certKeyEnc, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		panic(err)
	}
	certKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: certKeyEnc,
	})

	tpl := &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          certKey.Public(),
		Subject:            pkix.Name{CommonName: domain},
	}
	csrDer, err := x509.CreateCertificateRequest(rand.Reader, tpl, certKey)
	if err != nil {
		panic(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		panic(err)
	}

	order, err = client.FinalizeOrder(account, order, csr)
	if err != nil {
		panic(err)
	}

	certs, err := client.FetchCertificates(account, order.Certificate)
	if err != nil {
		panic(err)
	}

	err = myFs.Put(domainConfig.Private, string(certKeyPem), 0600)
	if err != nil {
		panic(err)
	}
	var certPem []byte
	for _, c := range certs {
		b := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})
		certPem = append(certPem, b...)
	}
	err = myFs.Put(domainConfig.Cert, string(certPem), 0600)
	if err != nil {
		panic(err)
	}
}
