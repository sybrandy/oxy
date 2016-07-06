package forward

import (
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/http"
	"strings"

	"github.com/vulcand/oxy/utils"
)

// Rewriter is responsible for removing hop-by-hop headers and setting forwarding headers
type ForwardCertRewriter struct {
	TrustForwardHeader bool
	Hostname           string
}

func (rw *ForwardCertRewriter) Rewrite(req *http.Request) {
    if !rw.TrustForwardHeader {
        req.Header.Del(XForwardedFor)
        req.Header.Del(XForwardedProto)
        req.Header.Del(XForwardedHost)
    }

    // By default, remove all Cert=related headers
    req.Header.Del(XForwardedSslClientCert)
    req.Header.Del(XSslClientSDn)
    req.Header.Del(XSslClientIDn)

	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
        if req.Header.Get(XForwardedFor) == "" {
            req.Header.Set(XForwardedFor, clientIP)
        }
		req.Header.Set(XRealIp, clientIP)
	}

	if req.Header.Get(XForwardedProto) == ""{
	    if req.TLS != nil {
            req.Header.Set(XForwardedProto, "https")
        } else {
            req.Header.Set(XForwardedProto, "http")
        }
	}

	if req.Header.Get(XForwardedHost) == "" {
        if req.Host != "" {
            req.Header.Set(XForwardedHost, req.Host)
        }
	}

	if rw.Hostname != "" {
		req.Header.Set(XForwardedServer, rw.Hostname)
	}

	// OPTIONS requests do not use authorization, therefore do not pass the
	// headers along.
	if strings.ToUpper(req.Method) != "OPTIONS" && req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		c := req.TLS.PeerCertificates[0]
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		}
		req.Header.Set(XForwardedSslClientCert,
			strings.Replace(string(pem.EncodeToMemory(block)), "\n", " ", -1))
		req.Header.Set(XSslClientSDn, pkixToString(c.Subject))
		req.Header.Set(XSslClientIDn, pkixToString(c.Issuer))
	}

	// Remove hop-by-hop headers to the backend.  Especially important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	utils.RemoveHeaders(req.Header, HopHeaders...)
}

func pkixToString(val pkix.Name) string {
	var parts []string
	for _, v := range val.Country {
		parts = append(parts, "C="+v)
	}
	for _, v := range val.Organization {
		parts = append(parts, "O="+v)
	}
	for _, v := range val.OrganizationalUnit {
		parts = append(parts, "OU="+v)
	}
	for _, v := range val.Locality {
		parts = append(parts, "L="+v)
	}
	for _, v := range val.Province {
		parts = append(parts, "ST="+v)
	}
	for _, v := range val.PostalCode {
		parts = append(parts, "PC="+v)
	}
	if val.SerialNumber != "" {
		parts = append(parts, "SERIALNUMBER="+val.SerialNumber)
	}
	if val.CommonName != "" {
		parts = append(parts, "CN="+val.CommonName)
	}
	return "/" + strings.Join(parts, "/")
}
