package forward

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"net/http"
	"testing"
)

var certBytes = "308203223082028ba00302010202106edf0d9499fd4533dd1297fc42a93be1300d06092a864886" +
	"f70d0101050500304c310b3009060355040613025a4131253023060355040a131c546861777465" +
	"20436f6e73756c74696e67202850747929204c74642e311630140603550403130d546861777465" +
	"20534743204341301e170d3039303332353136343932395a170d3130303332353136343932395a" +
	"3069310b3009060355040613025553311330110603550408130a43616c69666f726e6961311630" +
	"140603550407130d4d6f756e7461696e205669657731133011060355040a130a476f6f676c6520" +
	"496e63311830160603550403130f6d61696c2e676f6f676c652e636f6d30819f300d06092a8648" +
	"86f70d010101050003818d0030818902818100c5d6f892fccaf5614b064149e80a2c9581a218ef" +
	"41ec35bd7a58125ae76f9ea54ddc893abbeb029f6b73616bf0ffd868791fba7af9c4aebf3706ba" +
	"3eeaeed27435b4ddcfb157c05f351d66aa87fee0de072d66d773affbd36ab78bef090e0cc861a9" +
	"03ac90dd98b51c9c41566c017f0beec3bff391051ffba0f5cc6850ad2a590203010001a381e730" +
	"81e430280603551d250421301f06082b0601050507030106082b06010505070302060960864801" +
	"86f842040130360603551d1f042f302d302ba029a0278625687474703a2f2f63726c2e74686177" +
	"74652e636f6d2f54686177746553474343412e63726c307206082b060105050701010466306430" +
	"2206082b060105050730018616687474703a2f2f6f6373702e7468617774652e636f6d303e0608" +
	"2b060105050730028632687474703a2f2f7777772e7468617774652e636f6d2f7265706f736974" +
	"6f72792f5468617774655f5347435f43412e637274300c0603551d130101ff04023000300d0609" +
	"2a864886f70d01010505000381810062f1f3050ebc105e497c7aedf87e24d2f4a986bb3b837bd1" +
	"9b91ebcad98b065992f6bd2b49b7d6d3cb2e427a99d606c7b1d46352527fac39e6a8b6726de5bf" +
	"70212a52cba07634a5e332011bd1868e78eb5e3c93cf03072276786f207494feaa0ed9d53b2110" +
	"a76571f90209cdae884385c882587030ee15f33d761e2e45a6bc308203233082028ca003020102" +
	"020430000002300d06092a864886f70d0101050500305f310b3009060355040613025553311730" +
	"15060355040a130e566572695369676e2c20496e632e31373035060355040b132e436c61737320" +
	"33205075626c6963205072696d6172792043657274696669636174696f6e20417574686f726974" +
	"79301e170d3034303531333030303030305a170d3134303531323233353935395a304c310b3009" +
	"060355040613025a4131253023060355040a131c54686177746520436f6e73756c74696e672028" +
	"50747929204c74642e311630140603550403130d5468617774652053474320434130819f300d06" +
	"092a864886f70d010101050003818d0030818902818100d4d367d08d157faecd31fe7d1d91a13f" +
	"0b713cacccc864fb63fc324b0794bd6f80ba2fe10493c033fc093323e90b742b71c403c6d2cde2" +
	"2ff50963cdff48a500bfe0e7f388b72d32de9836e60aad007bc4644a3b847503f270927d0e62f5" +
	"21ab693684317590f8bfc76c881b06957cc9e5a8de75a12c7a68dfd5ca1c875860190203010001" +
	"a381fe3081fb30120603551d130101ff040830060101ff020100300b0603551d0f040403020106" +
	"301106096086480186f842010104040302010630280603551d110421301fa41d301b3119301706" +
	"035504031310507269766174654c6162656c332d313530310603551d1f042a30283026a024a022" +
	"8620687474703a2f2f63726c2e766572697369676e2e636f6d2f706361332e63726c303206082b" +
	"0601050507010104263024302206082b060105050730018616687474703a2f2f6f6373702e7468" +
	"617774652e636f6d30340603551d25042d302b06082b0601050507030106082b06010505070302" +
	"06096086480186f8420401060a6086480186f845010801300d06092a864886f70d010105050003" +
	"81810055ac63eadea1ddd2905f9f0bce76be13518f93d9052bc81b774bad6950a1eededcfddb07" +
	"e9e83994dcab72792f06bfab8170c4a8edea5334edef1e53d906c7562bd15cf4d18a8eb42bb137" +
	"9048084225c53e8acb7feb6f04d16dc574a2f7a27c7b603c77cd0ece48027f012fb69b37e02a2a" +
	"36dcd585d6ace53f546f961e05af"

var decodedCert string = "-----BEGIN CERTIFICATE-----" +
	" MIIDIjCCAougAwIBAgIQbt8NlJn9RTPdEpf8Qqk74TANBgkqhkiG9w0BAQUFADBM" +
	" MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg" +
	" THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0wOTAzMjUxNjQ5MjlaFw0x" +
	" MDAzMjUxNjQ5MjlaMGkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh" +
	" MRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgSW5jMRgw" +
	" FgYDVQQDEw9tYWlsLmdvb2dsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ" +
	" AoGBAMXW+JL8yvVhSwZBSegKLJWBohjvQew1vXpYElrnb56lTdyJOrvrAp9rc2Fr" +
	" 8P/YaHkfunr5xK6/Nwa6Puru0nQ1tN3PsVfAXzUdZqqH/uDeBy1m13Ov+9Nqt4vv" +
	" CQ4MyGGpA6yQ3Zi1HJxBVmwBfwvuw7/zkQUf+6D1zGhQrSpZAgMBAAGjgecwgeQw" +
	" KAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUFBwMCBglghkgBhvhCBAEwNgYDVR0f" +
	" BC8wLTAroCmgJ4YlaHR0cDovL2NybC50aGF3dGUuY29tL1RoYXd0ZVNHQ0NBLmNy" +
	" bDByBggrBgEFBQcBAQRmMGQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLnRoYXd0" +
	" ZS5jb20wPgYIKwYBBQUHMAKGMmh0dHA6Ly93d3cudGhhd3RlLmNvbS9yZXBvc2l0" +
	" b3J5L1RoYXd0ZV9TR0NfQ0EuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEF" +
	" BQADgYEAYvHzBQ68EF5JfHrt+H4k0vSphrs7g3vRm5HrytmLBlmS9r0rSbfW08su" +
	" QnqZ1gbHsdRjUlJ/rDnmqLZybeW/cCEqUsugdjSl4zIBG9GGjnjrXjyTzwMHInZ4" +
	" byB0lP6qDtnVOyEQp2Vx+QIJza6IQ4XIglhwMO4V8z12Hi5Fprw=" +
	" -----END CERTIFICATE----- "

var pkixMap = map[string]pkix.Name{
	"/C=US/O=ABC/OU=OU1/L=Local1/ST=CA/PC=12345/SERIALNUMBER=Serial12345/CN=John Doe": {
		Country:            []string{"US"},
		Organization:       []string{"ABC"},
		OrganizationalUnit: []string{"OU1"},
		Locality:           []string{"Local1"},
		Province:           []string{"CA"},
		PostalCode:         []string{"12345"},
		SerialNumber:       "Serial12345",
		CommonName:         "John Doe",
	},
	"/C=US/C=CA/C=ME/O=ABC/O=DEF/O=GHI/OU=OU1/OU=OU2/OU=OU3/L=Local1/L=Local2/L=Local3/ST=CA/ST=AK/ST=NY/PC=12345/PC=67890/PC=13579/SERIALNUMBER=Serial12345/CN=John Doe": {
		Country:            []string{"US", "CA", "ME"},
		Organization:       []string{"ABC", "DEF", "GHI"},
		OrganizationalUnit: []string{"OU1", "OU2", "OU3"},
		Locality:           []string{"Local1", "Local2", "Local3"},
		Province:           []string{"CA", "AK", "NY"},
		PostalCode:         []string{"12345", "67890", "13579"},
		SerialNumber:       "Serial12345",
		CommonName:         "John Doe",
	},
	"/": {},
}

func TestPkixToString(t *testing.T) {
	for key, val := range pkixMap {
		temp := pkixToString(val)
		if key != temp {
			t.Errorf("Key does not match generated string: \n\tKey: %s\n\tVal: %s\n", key, temp)
			t.Errorf("Diff: %s\n", diff(key, temp))
		}
	}
}

func TestForwardCertRewriteSimple(t *testing.T) {
	req := http.Request{
		Method:     "GET",
		RemoteAddr: "SomeHost:9999",
		Header:     map[string][]string{},
		Host:       "ThisHost",
	}
	rw := ForwardCertRewriter{
		TrustForwardHeader: true,
		Hostname:           "ServerName",
	}
	rw.Rewrite(&req)

	if req.Header.Get(XForwardedFor) != "SomeHost" {
		t.Errorf("Incorrect value for X-Forwarded-For: %+v\n", req.Header.Get(XForwardedFor))
	}
	if req.Header.Get(XForwardedProto) != "http" {
		t.Errorf("Incorrect value for X-Forwarded-Proto: %+v\n", req.Header.Get(XForwardedProto))
	}
	if req.Header.Get(XForwardedHost) != "ThisHost" {
		t.Errorf("Incorrect value for X-Forwarded-Host: %+v\n", req.Header.Get(XForwardedHost))
	}
	if req.Header.Get(XForwardedServer) != "ServerName" {
		t.Errorf("Incorrect value for X-Forwarded-Server: %+v\n", req.Header.Get(XForwardedServer))
	}
	if req.Header.Get(XRealIp) != "SomeHost" {
		t.Errorf("Incorrect value for X-Real-IP: %+v\n", req.Header.Get(XRealIp))
	}
}

func TestForwardCertRewriteNoHostname(t *testing.T) {
	req := http.Request{
		Method:     "GET",
		RemoteAddr: "SomeHost:9999",
		Header:     map[string][]string{},
		Host:       "ThisHost",
	}
	rw := ForwardCertRewriter{
		TrustForwardHeader: true,
	}
	rw.Rewrite(&req)

	if req.Header.Get(XForwardedFor) != "SomeHost" {
		t.Errorf("Incorrect value for X-Forwarded-For: %+v\n", req.Header.Get(XForwardedFor))
	}
	if req.Header.Get(XForwardedProto) != "http" {
		t.Errorf("Incorrect value for X-Forwarded-Proto: %+v\n", req.Header.Get(XForwardedProto))
	}
	if req.Header.Get(XForwardedHost) != "ThisHost" {
		t.Errorf("Incorrect value for X-Forwarded-Host: %+v\n", req.Header.Get(XForwardedHost))
	}
	if len(req.Header.Get(XForwardedServer)) != 0 {
		t.Errorf("Incorrect value for X-Forwarded-Server: %+v\n", req.Header.Get(XForwardedServer))
	}
	if req.Header.Get(XRealIp) != "SomeHost" {
		t.Errorf("Incorrect value for X-Real-IP: %+v\n", req.Header.Get(XRealIp))
	}
}

func TestForwardCertRewriteNoRemoteAddr(t *testing.T) {
	req := http.Request{
		Method:     "GET",
		RemoteAddr: "",
		Header:     map[string][]string{},
		Host:       "ThisHost",
	}
	rw := ForwardCertRewriter{
		TrustForwardHeader: true,
		Hostname:           "ServerName",
	}
	rw.Rewrite(&req)

	if len(req.Header.Get(XForwardedFor)) != 0 {
		t.Errorf("Incorrect value for X-Forwarded-For: %+v\n", req.Header.Get(XForwardedFor))
	}
	if req.Header.Get(XForwardedProto) != "http" {
		t.Errorf("Incorrect value for X-Forwarded-Proto: %+v\n", req.Header.Get(XForwardedProto))
	}
	if req.Header.Get(XForwardedHost) != "ThisHost" {
		t.Errorf("Incorrect value for X-Forwarded-Host: %+v\n", req.Header.Get(XForwardedHost))
	}
	if req.Header.Get(XForwardedServer) != "ServerName" {
		t.Errorf("Incorrect value for X-Forwarded-Server: %+v\n", req.Header.Get(XForwardedServer))
	}
	if len(req.Header.Get(XRealIp)) != 0 {
		t.Errorf("Incorrect value for X-Real-IP: %+v\n", req.Header.Get(XRealIp))
	}
}

func TestForwardCertRewritePresetHeaders(t *testing.T) {
	req := http.Request{
		Method:     "GET",
		RemoteAddr: "SomeHost:9999",
		Header: map[string][]string{
			XForwardedFor:   {"ForwardedHost"},
			XForwardedProto: {"Proto"},
			XForwardedHost:  {"ThisForwardedHost"},
		},
		Host: "ThisHost",
	}
	rw := ForwardCertRewriter{
		TrustForwardHeader: true,
		Hostname:           "ServerName",
	}
	rw.Rewrite(&req)

	if req.Header.Get(XForwardedFor) != "ForwardedHost" {
		t.Errorf("Incorrect value for X-Forwarded-For: %+v\n", req.Header.Get(XForwardedFor))
	}
	if req.Header.Get(XForwardedProto) != "Proto" {
		t.Errorf("Incorrect value for X-Forwarded-Proto: %+v\n", req.Header.Get(XForwardedProto))
	}
	if req.Header.Get(XForwardedHost) != "ThisForwardedHost" {
		t.Errorf("Incorrect value for X-Forwarded-Host: %+v\n", req.Header.Get(XForwardedHost))
	}
	if req.Header.Get(XForwardedServer) != "ServerName" {
		t.Errorf("Incorrect value for X-Forwarded-Server: %+v\n", req.Header.Get(XForwardedServer))
	}
	if req.Header.Get(XRealIp) != "SomeHost" {
		t.Errorf("Incorrect value for X-Real-IP: %+v\n", req.Header.Get(XRealIp))
	}
}

func TestForwardCertRewriteUntrustedPresetHeaders(t *testing.T) {
	req := http.Request{
		Method:     "GET",
		RemoteAddr: "SomeHost:9999",
		Header: map[string][]string{
			XForwardedFor:   {"ForwardedHost"},
			XForwardedProto: {"Proto"},
			XForwardedHost:  {"ThisForwardedHost"},
		},
		Host: "ThisHost",
	}
	rw := ForwardCertRewriter{
		TrustForwardHeader: false,
		Hostname:           "ServerName",
	}
	rw.Rewrite(&req)

	if req.Header.Get(XForwardedFor) != "SomeHost" {
		t.Errorf("Incorrect value for X-Forwarded-For: %+v\n", req.Header.Get(XForwardedFor))
	}
	if req.Header.Get(XForwardedProto) != "http" {
		t.Errorf("Incorrect value for X-Forwarded-Proto: %+v\n", req.Header.Get(XForwardedProto))
	}
	if req.Header.Get(XForwardedHost) != "ThisHost" {
		t.Errorf("Incorrect value for X-Forwarded-Host: %+v\n", req.Header.Get(XForwardedHost))
	}
	if req.Header.Get(XForwardedServer) != "ServerName" {
		t.Errorf("Incorrect value for X-Forwarded-Server: %+v\n", req.Header.Get(XForwardedServer))
	}
	if req.Header.Get(XRealIp) != "SomeHost" {
		t.Errorf("Incorrect value for X-Real-IP: %+v\n", req.Header.Get(XRealIp))
	}
}

func TestForwardCertRewriteRemoveHeaders(t *testing.T) {
	req := http.Request{
		Method:     "GET",
		RemoteAddr: "SomeHost:9999",
		Header: map[string][]string{
			Connection:              {"keep-alive"},
			Upgrade:                 {"HTTP/3.0"},
			XForwardedSslClientCert: {"CERT"},
			XSslClientSDn:           {"SDN"},
			XSslClientIDn:           {"IDN"},
		},
		Host: "ThisHost",
	}
	rw := ForwardCertRewriter{
		TrustForwardHeader: false,
		Hostname:           "ServerName",
	}
	rw.Rewrite(&req)

	if len(req.Header.Get(Connection)) != 0 {
		t.Errorf("Incorrect value for Connection: %+v\n", req.Header.Get(Connection))
	}
	if len(req.Header.Get(Upgrade)) != 0 {
		t.Errorf("Incorrect value for Upgrade: %+v\n", req.Header.Get(Upgrade))
	}
	if len(req.Header.Get(XForwardedSslClientCert)) != 0 {
		t.Errorf("Incorrect value for XForwardedSslClientCert: %+v\n", req.Header.Get(XForwardedSslClientCert))
	}
	if len(req.Header.Get(XSslClientSDn)) != 0 {
		t.Errorf("Incorrect value for XSslClientSDn: %+v\n", req.Header.Get(XSslClientSDn))
	}
	if len(req.Header.Get(XSslClientIDn)) != 0 {
		t.Errorf("Incorrect value for XSslClientIDn: %+v\n", req.Header.Get(XSslClientIDn))
	}
}

func TestForwardCertRewriteTLS(t *testing.T) {
	s, _ := hex.DecodeString(certBytes)
	certs, err := x509.ParseCertificates(s)
	if err != nil {
		t.Fatal("Could not parse the test certificate.")
	}
	req := http.Request{
		Method:     "GET",
		RemoteAddr: "SomeHost:9999",
		Header:     map[string][]string{},
		Host:       "ThisHost",
		TLS: &tls.ConnectionState{
			PeerCertificates: certs,
		},
	}
	rw := ForwardCertRewriter{
		TrustForwardHeader: true,
		Hostname:           "ServerName",
	}
	rw.Rewrite(&req)

	if req.Header.Get(XForwardedFor) != "SomeHost" {
		t.Errorf("Incorrect value for X-Forwarded-For: %+v\n", req.Header.Get(XForwardedFor))
	}
	if req.Header.Get(XForwardedProto) != "https" {
		t.Errorf("Incorrect value for X-Forwarded-Proto: %+v\n", req.Header.Get(XForwardedProto))
	}
	if req.Header.Get(XForwardedHost) != "ThisHost" {
		t.Errorf("Incorrect value for X-Forwarded-Host: %+v\n", req.Header.Get(XForwardedHost))
	}
	if req.Header.Get(XForwardedServer) != "ServerName" {
		t.Errorf("Incorrect value for X-Forwarded-Server: %+v\n", req.Header.Get(XForwardedServer))
	}
	if req.Header.Get(XRealIp) != "SomeHost" {
		t.Errorf("Incorrect value for X-Real-IP: %+v\n", req.Header.Get(XRealIp))
	}
	if req.Header.Get(XForwardedSslClientCert) != decodedCert {
		t.Errorf("Incorrect value for X-Forwarded-SSL-Client-Cert: %+v\n", req.Header.Get(XForwardedSslClientCert))
		t.Errorf("Lengths: %d, %d", len(decodedCert), len(req.Header.Get(XForwardedSslClientCert)))
		t.Errorf(diff(decodedCert, req.Header.Get(XForwardedSslClientCert)))
	}
	if req.Header.Get(XSslClientSDn) != "/C=US/O=Google Inc/L=Mountain View/ST=California/CN=mail.google.com" {
		t.Errorf("Incorrect value for X-SSL-Client-S-DN: %+v\n", req.Header.Get(XSslClientSDn))
	}
	if req.Header.Get(XSslClientIDn) != "/C=ZA/O=Thawte Consulting (Pty) Ltd./CN=Thawte SGC CA" {
		t.Errorf("Incorrect value for X-SSL-Client-I-DN: %+v\n", req.Header.Get(XSslClientIDn))
	}
}

func TestForwardCertRewriteTLSOptionsMethod(t *testing.T) {
	s, _ := hex.DecodeString(certBytes)
	certs, err := x509.ParseCertificates(s)
	if err != nil {
		t.Fatal("Could not parse the test certificate.")
	}
	req := http.Request{
		Method:     "options",
		RemoteAddr: "SomeHost:9999",
		Header:     map[string][]string{},
		Host:       "ThisHost",
		TLS: &tls.ConnectionState{
			PeerCertificates: certs,
		},
	}
	rw := ForwardCertRewriter{
		TrustForwardHeader: true,
		Hostname:           "ServerName",
	}
	rw.Rewrite(&req)

	if req.Header.Get(XForwardedFor) != "SomeHost" {
		t.Errorf("Incorrect value for X-Forwarded-For: %+v\n", req.Header.Get(XForwardedFor))
	}
	if req.Header.Get(XForwardedProto) != "https" {
		t.Errorf("Incorrect value for X-Forwarded-Proto: %+v\n", req.Header.Get(XForwardedProto))
	}
	if req.Header.Get(XForwardedHost) != "ThisHost" {
		t.Errorf("Incorrect value for X-Forwarded-Host: %+v\n", req.Header.Get(XForwardedHost))
	}
	if req.Header.Get(XForwardedServer) != "ServerName" {
		t.Errorf("Incorrect value for X-Forwarded-Server: %+v\n", req.Header.Get(XForwardedServer))
	}
	if req.Header.Get(XRealIp) != "SomeHost" {
		t.Errorf("Incorrect value for X-Real-IP: %+v\n", req.Header.Get(XRealIp))
	}
	if len(req.Header.Get(XForwardedSslClientCert)) != 0 {
		t.Errorf("Incorrect value for X-Forwarded-SSL-Client-Cert: %+v\n", req.Header.Get(XForwardedSslClientCert))
	}
	if len(req.Header.Get(XSslClientSDn)) != 0 {
		t.Errorf("Incorrect value for X-SSL-Client-S-DN: %+v\n", req.Header.Get(XSslClientSDn))
	}
	if len(req.Header.Get(XSslClientIDn)) != 0 {
		t.Errorf("Incorrect value for X-SSL-Client-I-DN: %+v\n", req.Header.Get(XSslClientIDn))
	}
}

func diff(str1, str2 string) string {
	var outBuff []byte
	buff1 := bytes.NewBufferString(str1).Bytes()
	buff2 := bytes.NewBufferString(str2).Bytes()
	i := 0
	j := 0
	for i < len(buff1) && j < len(buff2) {
		if buff1[i] == buff2[i] {
			outBuff = append(outBuff, buff1[i])
		} else {
			outBuff = append(outBuff, '<', buff1[i], '|', buff2[i], '>')
		}
		i++
		j++
	}
	return string(outBuff)
}
