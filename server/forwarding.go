// Copyright (c) 2014 The SkyDNS Authors. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"fmt"

	"github.com/miekg/dns"
)

// ServeDNSForward forwards a request to a nameservers and returns the response.
func (self *Server) ServeDNSForward(w dns.ResponseWriter, req *dns.Msg) *dns.Msg {

	if self.config.NoRec {
		m := new(dns.Msg)
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		m.Authoritative = false
		m.RecursionAvailable = false
		w.WriteMsg(m)
		return m
	}

	if len(self.config.Nameservers) == 0 || dns.CountLabel(req.Question[0].Name) < self.config.Ndots {
		if self.config.Verbose {
			if len(self.config.Nameservers) == 0 {
				logger.Infof("can not forward, no nameservers defined")
			} else {
				logger.Infof("can not forward, name too short (less than %d labels): `%s'", self.config.Ndots, req.Question[0].Name)
			}
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		m.Authoritative = false     // no matter what set to false
		m.RecursionAvailable = true // and this is still true
		w.WriteMsg(m)
		return m
	}

	tcp := isTCP(w)

	var (
		r   *dns.Msg
		err error
		try int
	)

	nsid := 0
	if self.config.NSRotate {
		// Use request Id for "random" nameserver selection.
		nsid = int(req.Id) % len(self.config.Nameservers)
	}
Redo:
	switch tcp {
	case false:
		r, _, err = self.dnsUDPclient.Exchange(req, self.config.Nameservers[nsid])
	case true:
		r, _, err = self.dnsTCPclient.Exchange(req, self.config.Nameservers[nsid])
	}
	if err == nil {
		r.Compress = true
		r.Id = req.Id
		w.WriteMsg(r)
		return r
	}
	// Seen an error, this can only mean, "server not reached", try again
	// but only if we have not exausted our nameservers.
	if try < len(self.config.Nameservers) {
		try++
		nsid = (nsid + 1) % len(self.config.Nameservers)
		goto Redo
	}

	logger.Errorf("failure to forward request %q", err.Error())
	m := new(dns.Msg)
	m.SetReply(req)
	m.SetRcode(req, dns.RcodeServerFailure)
	w.WriteMsg(m)
	return m
}

// ServeDNSReverse is the handler for DNS requests for the reverse zone. If nothing is found
// locally the request is forwarded to the forwarder for resolution.
func (self *Server) ServeDNSReverse(w dns.ResponseWriter, req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Compress = true
	m.Authoritative = false // Set to false, because I don't know what to do wrt DNSSEC.
	m.RecursionAvailable = true
	var err error
	if m.Answer, err = self.PTRRecords(req.Question[0]); err == nil {
		// TODO(miek): Reverse DNSSEC. We should sign this, but requires a key....and more
		// Probably not worth the hassle?
		if err := w.WriteMsg(m); err != nil {
			logger.Errorf("failure to return reply %q", err.Error())
		}
		return m
	}
	// Always forward if not found locally.
	return self.ServeDNSForward(w, req)
}

// Lookup looks up name,type using the recursive nameserver defines
// in the server's config. If none defined it returns an error.
func (self *Server) Lookup(n string, t, bufsize uint16, dnssec bool) (*dns.Msg, error) {

	if len(self.config.Nameservers) == 0 {
		return nil, fmt.Errorf("no nameservers configured can not lookup name")
	}
	if dns.CountLabel(n) < self.config.Ndots {
		return nil, fmt.Errorf("name has fewer than %d labels", self.config.Ndots)
	}
	m := new(dns.Msg)
	m.SetQuestion(n, t)
	m.SetEdns0(bufsize, dnssec)

	nsid := int(m.Id) % len(self.config.Nameservers)
	try := 0
Redo:
	r, _, err := self.dnsUDPclient.Exchange(m, self.config.Nameservers[nsid])
	if err == nil {
		if r.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("rcode is not equal to success")
		}
		// Reset TTLs to rcache TTL to make some of the other code
		// and the tests not care about TTLs
		for _, rr := range r.Answer {
			rr.Header().Ttl = uint32(self.config.RCacheTtl)
		}
		for _, rr := range r.Extra {
			rr.Header().Ttl = uint32(self.config.RCacheTtl)
		}
		return r, nil
	}
	// Seen an error, this can only mean, "server not reached", try again
	// but only if we have not exausted our nameservers.
	if try < len(self.config.Nameservers) {
		try++
		nsid = (nsid + 1) % len(self.config.Nameservers)
		goto Redo
	}
	return nil, fmt.Errorf("failure to lookup name")
}
