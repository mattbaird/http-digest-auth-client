package http_digest_auth

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	connectTimeOut   = time.Duration(10 * time.Second)
	readWriteTimeout = time.Duration(20 * time.Second)
	userAgent        = "AtScale"
)

type myjar struct {
	jar map[string][]*http.Cookie
}

func (p *myjar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.jar[u.Host] = cookies
}

func (p *myjar) Cookies(u *url.URL) []*http.Cookie {
	return p.jar[u.Host]
}

const (
	nc = "00000001"
)

func Auth(username string, password string, uri string) (bool, error) {
	client := DefaultTimeoutClient()
	jar := &myjar{}
	jar.jar = make(map[string][]*http.Cookie)
	client.Jar = jar
	var req *http.Request
	var resp *http.Response
	var err error
	req, err = http.NewRequest("GET", uri, nil)
	if err != nil {
		return false, err
	}
	headers := http.Header{
		"User-Agent":      []string{userAgent},
		"Accept":          []string{"*/*"},
		"Accept-Encoding": []string{"identity"},
		"Connection":      []string{"Keep-Alive"},
		"Host":            []string{req.Host},
	}
	req.Header = headers

	resp, err = client.Do(req)
	if err != nil {
		return false, err
	}
	// you HAVE to read the whole body and then close it to reuse the http connection
	// otherwise it *could* fail in certain environments (behind proxy for instance)
	io.Copy(ioutil.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		var authorization map[string]string = DigestAuthParams(resp)
		realmHeader := authorization["realm"]
		qopHeader := authorization["qop"]
		nonceHeader := authorization["nonce"]
		opaqueHeader := authorization["opaque"]
		algorithm := authorization["algorithm"]
		realm := realmHeader
		// A1
		h := md5.New()
		A1 := fmt.Sprintf("%s:%s:%s", username, realm, password)
		io.WriteString(h, A1)
		HA1 := hex.EncodeToString(h.Sum(nil))

		// A2
		h = md5.New()
		A2 := fmt.Sprintf("GET:%s", "/auth")
		io.WriteString(h, A2)
		HA2 := hex.EncodeToString(h.Sum(nil))

		// response
		cnonce := RandomKey()
		response := H(strings.Join([]string{HA1, nonceHeader, nc, cnonce, qopHeader, HA2}, ":"))

		// now make header
		AuthHeader := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", qop=%s, nc=%s, cnonce="%s", opaque="%s", algorithm="%s"`,
			username, realmHeader, nonceHeader, "/auth", response, qopHeader, nc, cnonce, opaqueHeader, algorithm)

		headers := http.Header{
			"User-Agent":      []string{userAgent},
			"Accept":          []string{"*/*"},
			"Accept-Encoding": []string{"identity"},
			"Connection":      []string{"Keep-Alive"},
			"Host":            []string{req.Host},
			"Authorization":   []string{AuthHeader},
		}
		//req, err = http.NewRequest("GET", uri, nil)
		req.Header = headers
		resp, err = client.Do(req)
		if err != nil {
			return false, err
		}
		defer resp.Body.Close()
	} else {
		return false, fmt.Errorf("response status code should have been 401, it was %v", resp.StatusCode)
	}
	return resp.StatusCode == http.StatusOK, err
}

/*
 Parse Authorization header from the http.Request. Returns a map of
 auth parameters or nil if the header is not a valid parsable Digest
 auth header.
*/
func DigestAuthParams(r *http.Response) map[string]string {
	s := strings.SplitN(r.Header.Get("Www-Authenticate"), " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	result := map[string]string{}
	for _, kv := range strings.Split(s[1], ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.Trim(parts[0], "\" ")] = strings.Trim(parts[1], "\" ")
	}
	return result
}
func RandomKey() string {
	k := make([]byte, 8)
	for bytes := 0; bytes < len(k); {
		n, err := rand.Read(k[bytes:])
		if err != nil {
			panic("rand.Read() failed")
		}
		bytes += n
	}
	return base64.StdEncoding.EncodeToString(k)
}

/*
 H function for MD5 algorithm (returns a lower-case hex MD5 digest)
*/
func H(data string) string {
	digest := md5.New()
	digest.Write([]byte(data))
	return hex.EncodeToString(digest.Sum(nil))
}

func timeoutDialer(cTimeout time.Duration, rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		if rwTimeout > 0 {
			conn.SetDeadline(time.Now().Add(rwTimeout))
		}
		return conn, nil
	}
}

// apps will set three OS variables:
// atscale_http_sslcert - location of the http ssl cert
// atscale_http_sslkey - location of the http ssl key
// atscale_disable_keepalives - disable http keep alives
func NewTimeoutClient(cTimeout time.Duration, rwTimeout time.Duration) *http.Client {
	certLocation := os.Getenv("atscale_http_sslcert")
	keyLocation := os.Getenv("atscale_http_sslkey")
	disableKeepAlives := os.Getenv("atscale_disable_keepalives")
	disableKeepAlivesBool := false
	if disableKeepAlives == "true" {
		disableKeepAlivesBool = true
	}

	// default
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	if len(certLocation) > 0 && len(keyLocation) > 0 {
		// Load client cert if available
		cert, err := tls.LoadX509KeyPair(certLocation, keyLocation)
		if err == nil {
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		} else {
			fmt.Printf("Error loading X509 Key Pair:%v\n", err)
		}
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			DisableKeepAlives: disableKeepAlivesBool,
			Dial:              timeoutDialer(cTimeout, rwTimeout),
		},
	}
}

func DefaultTimeoutClient() *http.Client {
	return NewTimeoutClient(connectTimeOut, readWriteTimeout)
}
