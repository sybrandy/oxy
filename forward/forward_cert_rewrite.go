package forward

import (
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
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if rw.TrustForwardHeader {
			if prior, ok := req.Header[XForwardedFor]; ok {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
		}
		req.Header.Set(XForwardedFor, clientIP)
	}

	if xfp := req.Header.Get(XForwardedProto); xfp != "" && rw.TrustForwardHeader {
		req.Header.Set(XForwardedProto, xfp)
	} else if req.TLS != nil {
		req.Header.Set(XForwardedProto, "https")
	} else {
		req.Header.Set(XForwardedProto, "http")
	}

	if xfh := req.Header.Get(XForwardedHost); xfh != "" && rw.TrustForwardHeader {
		req.Header.Set(XForwardedHost, xfh)
	} else if req.Host != "" {
		req.Header.Set(XForwardedHost, req.Host)
	}

	if rw.Hostname != "" {
		req.Header.Set(XForwardedServer, rw.Hostname)
	}

    if req.RemoteAddr != "" {
        req.Header.Set(XRealIp, strings.Split(req.RemoteAddr, ":")[0])
    }

    if req.TLS != nil {
        numCerts := len(req.TLS.PeerCertificates)
        certs := make([]string, numCerts)
        subjects := make([]string, numCerts)
        issuers := make([]string, numCerts)
        for i, c := range req.TLS.PeerCertificates {
            certs[i] = strings.Replace(string(c.Raw), "\n", " ", -1)
            subjects[i] = strings.Replace(string(c.RawSubject), "\n", " ", -1)
            issuers[i] = strings.Replace(string(c.RawIssuer), "\n", " ", -1)
        }
        req.Header.Set(XForwardedSslClientCert, strings.Join(certs, ","))
        req.Header.Set(XSslClientSDn, strings.Join(subjects, ","))
        req.Header.Set(XSslClientIDn, strings.Join(issuers, ","))
    }

	// Remove hop-by-hop headers to the backend.  Especially important is "Connection" because we want a persistent
	// connection, regardless of what the client sent to us.
	utils.RemoveHeaders(req.Header, HopHeaders...)
}
