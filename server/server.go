package server

import (
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-etcd/etcd"
	"github.com/coreos/go-systemd/activation"
	"github.com/lostz/logging"
	"github.com/lostz/skydns/cache"
	"github.com/lostz/skydns/msg"
	"github.com/lostz/smartdns/config"
	"github.com/miekg/dns"
)

const Version = "2.5.2c"

var logger = logging.GetLogger("server")

type Server struct {
	backend Backend
	config  *config.Config

	group        *sync.WaitGroup
	dnsUDPclient *dns.Client // used for forwarding queries
	dnsTCPclient *dns.Client // used for forwarding queries
	scache       *cache.Cache
	rcache       *cache.Cache
}

type Backend interface {
	Records(name string, exact bool) ([]msg.Service, error)
	ReverseRecord(name string) (*msg.Service, error)
}

type FirstBackend []Backend

// FirstBackend implements Backend
var _ Backend = FirstBackend{}

func (g FirstBackend) Records(name string, exact bool) (records []msg.Service, err error) {
	var lastError error
	for _, backend := range g {
		if records, err = backend.Records(name, exact); err == nil && len(records) > 0 {
			return records, nil
		}
		if err != nil {
			lastError = err
		}
	}
	return nil, lastError
}

func (g FirstBackend) ReverseRecord(name string) (record *msg.Service, err error) {
	var lastError error
	for _, backend := range g {
		if record, err = backend.ReverseRecord(name); err == nil && record != nil {
			return record, nil
		}
		if err != nil {
			lastError = err
		}
	}
	return nil, lastError
}

func NewServer(backend Backend, config *config.Config) *Server {
	return &Server{
		backend: backend,
		config:  config,

		group:        new(sync.WaitGroup),
		scache:       cache.New(config.SCache, 0),
		rcache:       cache.New(config.RCache, config.RCacheTtl),
		dnsUDPclient: &dns.Client{Net: "udp", ReadTimeout: config.ReadTimeout, WriteTimeout: config.ReadTimeout, SingleInflight: true},
		dnsTCPclient: &dns.Client{Net: "tcp", ReadTimeout: config.ReadTimeout, WriteTimeout: config.ReadTimeout, SingleInflight: true},
	}
}

func (self *Server) hasDomain(name string) bool {
	for _, domain := range self.config.Domain {
		if strings.HasSuffix(name, domain) {
			return true
		}
	}

	return false
}

func (self *Server) getDomain(name string) string {
	for _, domain := range self.config.Domain {
		if strings.HasSuffix(name, domain) {
			return domain
		}
	}

	return ""
}

func (self *Server) getDnsDomain(name string) string {
	for _, domain := range self.config.DnsDomain {
		if strings.HasSuffix(name, domain) {
			return domain
		}
	}
	return ""

}
func (self *Server) getLocalDomain(name string) string {
	for _, domain := range self.config.LocalDomain {
		if strings.HasSuffix(name, domain) {
			return domain
		}
	}
	return ""
}

func (self *Server) Start() error {
	mux := dns.NewServeMux()
	mux.Handle(".", self)

	dnsReadyMsg := func(addr, net string) {
		if self.config.DNSSEC == "" {
			logger.Infof("ready for queries on %s for %s://%s [rcache %d]", self.config.Domain, net, addr, self.config.RCache)
		} else {
			logger.Infof("ready for queries on %s for %s://%s [rcache %d], signing with %s [scache %d]", self.config.Domain, net, addr, self.config.RCache, self.config.DNSSEC, self.config.SCache)
		}
	}

	if self.config.Systemd {
		packetConns, err := activation.PacketConns(false)
		if err != nil {
			return err
		}
		listeners, err := activation.Listeners(true)
		if err != nil {
			return err
		}
		if len(packetConns) == 0 && len(listeners) == 0 {
			return fmt.Errorf("no UDP or TCP sockets supplied by systemd")
		}
		for _, p := range packetConns {
			if u, ok := p.(*net.UDPConn); ok {
				self.group.Add(1)
				go func() {
					defer self.group.Done()
					if err := dns.ActivateAndServe(nil, u, mux); err != nil {
						logger.Errorf("dns.ActivateAndServe", err.Error())
					}
				}()
				dnsReadyMsg(u.LocalAddr().String(), "udp")
			}
		}
		for _, l := range listeners {
			if t, ok := l.(*net.TCPListener); ok {
				self.group.Add(1)
				go func() {
					defer self.group.Done()
					if err := dns.ActivateAndServe(t, nil, mux); err != nil {
						logger.Errorf("dns.ActivateAndServe", err.Error())
					}
				}()
				dnsReadyMsg(t.Addr().String(), "tcp")
			}
		}
	} else {
		self.group.Add(1)
		go func() {
			defer self.group.Done()
			if err := dns.ListenAndServe(self.config.DnsAddr, "tcp", mux); err != nil {
				logger.Errorf("dns.ListenAndServe", err.Error())
			}
		}()
		dnsReadyMsg(self.config.DnsAddr, "tcp")
		self.group.Add(1)
		go func() {
			defer self.group.Done()
			if err := dns.ListenAndServe(self.config.DnsAddr, "udp", mux); err != nil {
				logger.Errorf("dns.ListenAndServe", err.Error())
			}
		}()
		dnsReadyMsg(self.config.DnsAddr, "udp")
	}
	self.group.Wait()
	return nil
}

func (self *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Compress = true
	bufsize := uint16(512)
	dnssec := false
	tcp := false
	q := req.Question[0]
	name := strings.ToLower(q.Name)
	if q.Qtype == dns.TypeANY {
		m.Authoritative = false
		m.Rcode = dns.RcodeRefused
		m.RecursionAvailable = false
		m.RecursionDesired = false
		m.Compress = false
		// if write fails don't care
		w.WriteMsg(m)
		return
	}

	if o := req.IsEdns0(); o != nil {
		bufsize = o.UDPSize()
		dnssec = o.Do()
	}
	if bufsize < 512 {
		bufsize = 512
	}
	// with TCP we can send 64K
	if tcp = isTCP(w); tcp {
		bufsize = dns.MaxMsgSize - 1
	} else {
	}
	if self.config.Verbose {
		logger.Infof("received DNS Request for %q from %q with type %d", q.Name, w.RemoteAddr(), q.Qtype)
	}

	// Check cache first.
	m1 := self.rcache.Hit(q, dnssec, tcp, m.Id)
	if m1 != nil {
		if tcp {
			if _, overflow := Fit(m1, dns.MaxMsgSize, tcp); overflow {
				msgFail := new(dns.Msg)
				self.ServerFailure(msgFail, req)
				w.WriteMsg(msgFail)
				return
			}
		} else {
			// Overflow with udp always results in TC.
			Fit(m1, int(bufsize), tcp)
		}
		// Still round-robin even with hits from the cache.
		// Only shuffle A and AAAA records with each other.
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			self.RoundRobin(m1.Answer)
		}

		if err := w.WriteMsg(m1); err != nil {
			logger.Errorf("failure to return reply %q", err.Error())
		}
		return
	}

	if q.Qtype == dns.TypePTR && strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.") {
		resp := self.ServeDNSReverse(w, req)
		if resp != nil {
			self.rcache.InsertMessage(cache.Key(q, dnssec, tcp), resp)
		}
		return
	}

	if q.Qclass != dns.ClassCHAOS && !self.hasDomain(name) {
		resp := self.ServeDNSForward(w, req)
		if resp != nil {
			self.rcache.InsertMessage(cache.Key(q, dnssec, tcp), resp)
		}
		return
	}

	defer func() {
		if m.Rcode == dns.RcodeServerFailure {
			if err := w.WriteMsg(m); err != nil {
				logger.Errorf("failure to return reply %q", err.Error())
			}
			return
		}
		// Set TTL to the minimum of the RRset and dedup the message, i.e. remove identical RRs.
		m = self.dedup(m)

		minttl := self.config.Ttl
		if len(m.Answer) > 1 {
			for _, r := range m.Answer {
				if r.Header().Ttl < minttl {
					minttl = r.Header().Ttl
				}
			}
			for _, r := range m.Answer {
				r.Header().Ttl = minttl
			}
		}

		if tcp {
			if _, overflow := Fit(m, dns.MaxMsgSize, tcp); overflow {
				msgFail := new(dns.Msg)
				self.ServerFailure(msgFail, req)
				w.WriteMsg(msgFail)
				return
			}
		} else {
			Fit(m, int(bufsize), tcp)
		}
		self.rcache.InsertMessage(cache.Key(q, dnssec, tcp), m)

		if err := w.WriteMsg(m); err != nil {
			logger.Errorf("failure to return reply %q", err.Error())
		}
	}()

	if self.hasDomain(name) {
		if q.Qtype == dns.TypeSOA {
			m.Answer = []dns.RR{self.NewSOA(name)}
			return
		}
	}
	if q.Qclass == dns.ClassCHAOS {
		if q.Qtype == dns.TypeTXT {
			switch name {
			case "authors.bind.":
				fallthrough
			case "version.bind.":
				fallthrough
			case "version.server.":
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{Version}}}
				return
			case "hostname.bind.":
				fallthrough
			case "id.server.":
				// TODO(miek): machine name to return
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"localhost"}}}
				return
			default:
				if self.hasDomain(name) {
					hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
					authors := []string{"Erik St. Martin", "Brian Ketelsen", "Miek Gieben", "Michael Crosby"}
					for _, a := range authors {
						m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{a}})
					}
					for j := 0; j < len(authors)*(int(dns.Id())%4+1); j++ {
						q := int(dns.Id()) % len(authors)
						p := int(dns.Id()) % len(authors)
						if q == p {
							p = (p + 1) % len(authors)
						}
						m.Answer[q], m.Answer[p] = m.Answer[p], m.Answer[q]
					}
					return

				}
				return

			}
		}
		// still here, fail
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		return
	}

	switch q.Qtype {
	case dns.TypeNS:
		if !self.hasDomain(name) {
			break
		}
		// Lookup s.config.DnsDomain
		domain := self.getDnsDomain(name)
		records, extra, err := self.NSRecords(q, domain)
		if isEtcdNameError(err, self) {
			self.NameError(m, req, name)
			return
		}
		m.Answer = append(m.Answer, records...)
		m.Extra = append(m.Extra, extra...)
	case dns.TypeA, dns.TypeAAAA:
		records, err := self.AddressRecords(q, name, nil, bufsize, dnssec, false)
		if isEtcdNameError(err, self) {
			self.NameError(m, req, name)
			return
		}
		m.Answer = append(m.Answer, records...)
	case dns.TypeTXT:
		records, err := self.TXTRecords(q, name)
		if isEtcdNameError(err, self) {
			self.NameError(m, req, name)
			return
		}
		m.Answer = append(m.Answer, records...)
	case dns.TypeCNAME:
		records, err := self.CNAMERecords(q, name)
		if isEtcdNameError(err, self) {
			self.NameError(m, req, name)
			return
		}
		m.Answer = append(m.Answer, records...)
	case dns.TypeMX:
		records, extra, err := self.MXRecords(q, name, bufsize, dnssec)
		if isEtcdNameError(err, self) {
			self.NameError(m, req, name)
			return
		}
		m.Answer = append(m.Answer, records...)
		m.Extra = append(m.Extra, extra...)
	default:
		fallthrough // also catch other types, so that they return NODATA
	case dns.TypeSRV:
		records, extra, err := self.SRVRecords(q, name, bufsize, dnssec)
		if err != nil {
			if isEtcdNameError(err, self) {
				self.NameError(m, req, name)
				return
			}
			logger.Errorf("got error from backend: %s", err.Error())
			if q.Qtype == dns.TypeSRV { // Otherwise NODATA
				self.ServerFailure(m, req)
				return
			}
		}
		// if we are here again, check the types, because an answer may only
		// be given for SRV. All other types should return NODATA, the
		// NXDOMAIN part is handled in the above code. TODO(miek): yes this
		// can be done in a more elegant manor.
		if q.Qtype == dns.TypeSRV {
			m.Answer = append(m.Answer, records...)
			m.Extra = append(m.Extra, extra...)
		}
	}

	if len(m.Answer) == 0 { // NODATA response
		m.Ns = []dns.RR{self.NewSOA(name)}
		m.Ns[0].Header().Ttl = self.config.MinTtl
	}
}

func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}

func (self *Server) dedup(m *dns.Msg) *dns.Msg {
	// Answer section
	ma := make(map[string]dns.RR)
	for _, a := range m.Answer {
		// Or use Pack()... Think this function also could be placed in go dns.
		s1 := a.Header().Name
		s1 += strconv.Itoa(int(a.Header().Class))
		s1 += strconv.Itoa(int(a.Header().Rrtype))
		// there can only be one CNAME for an ownername
		if a.Header().Rrtype == dns.TypeCNAME {
			if _, ok := ma[s1]; ok {
				// already exist, randomly overwrite if roundrobin is true
				// Note: even with roundrobin *off* this depends on the
				// order we get the names.
				if self.config.RoundRobin && dns.Id()%2 == 0 {
					ma[s1] = a
					continue
				}
			}
			ma[s1] = a
			continue
		}
		for i := 1; i <= dns.NumField(a); i++ {
			s1 += dns.Field(a, i)
		}
		ma[s1] = a
	}
	// Only is our map is smaller than the #RR in the answer section we should reset the RRs
	// in the section it self
	if len(ma) < len(m.Answer) {
		i := 0
		for _, v := range ma {
			m.Answer[i] = v
			i++
		}
		m.Answer = m.Answer[:len(ma)]
	}

	// Additional section
	me := make(map[string]dns.RR)
	for _, e := range m.Extra {
		s1 := e.Header().Name
		s1 += strconv.Itoa(int(e.Header().Class))
		s1 += strconv.Itoa(int(e.Header().Rrtype))
		// there can only be one CNAME for an ownername
		if e.Header().Rrtype == dns.TypeCNAME {
			if _, ok := me[s1]; ok {
				// already exist, randomly overwrite if roundrobin is true
				if self.config.RoundRobin && dns.Id()%2 == 0 {
					me[s1] = e
					continue
				}
			}
			me[s1] = e
			continue
		}
		for i := 1; i <= dns.NumField(e); i++ {
			s1 += dns.Field(e, i)
		}
		me[s1] = e
	}

	if len(me) < len(m.Extra) {
		i := 0
		for _, v := range me {
			m.Extra[i] = v
			i++
		}
		m.Extra = m.Extra[:len(me)]
	}

	return m
}

func (self *Server) ServerFailure(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeServerFailure)
}

func (self *Server) RoundRobin(rrs []dns.RR) {
	if !self.config.RoundRobin {
		return
	}
	// If we have more than 1 CNAME don't touch the packet, because some stub resolver (=glibc)
	// can't deal with the returned packet if the CNAMEs need to be accesses in the reverse order.
	cname := 0
	for _, r := range rrs {
		if r.Header().Rrtype == dns.TypeCNAME {
			cname++
			if cname > 1 {
				return
			}
		}
	}

	switch l := len(rrs); l {
	case 2:
		if dns.Id()%2 == 0 {
			rrs[0], rrs[1] = rrs[1], rrs[0]
		}
	default:
		for j := 0; j < l*(int(dns.Id())%4+1); j++ {
			q := int(dns.Id()) % l
			p := int(dns.Id()) % l
			if q == p {
				p = (p + 1) % l
			}
			rrs[q], rrs[p] = rrs[p], rrs[q]
		}
	}

}

// SOA returns a SOA record for this SkyDNS instance.
func (self *Server) NewSOA(name string) dns.RR {
	domain := self.getDomain(name)
	return &dns.SOA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: self.config.Ttl},
		Ns:      appendDomain("ns.dns", domain),
		Mbox:    self.config.Hostmaster,
		Serial:  uint32(time.Now().Truncate(time.Hour).Unix()),
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  self.config.MinTtl,
	}
}

func (self *Server) NSRecords(q dns.Question, name string) (records []dns.RR, extra []dns.RR, err error) {
	services, err := self.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	services = msg.Group(services)

	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			return nil, nil, fmt.Errorf("NS record must be an IP address")
		case ip.To4() != nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewNS(q.Name, serv.Host))
			extra = append(extra, serv.NewA(serv.Host, ip.To4()))
		case ip.To4() == nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewNS(q.Name, serv.Host))
			extra = append(extra, serv.NewAAAA(serv.Host, ip.To16()))
		}
	}
	return records, extra, nil
}

func (self *Server) AddressRecords(q dns.Question, name string, previousRecords []dns.RR, bufsize uint16, dnssec, both bool) (records []dns.RR, err error) {
	services, err := self.backend.Records(name, false)
	if err != nil {
		return nil, err
	}

	services = msg.Group(services)

	for _, serv := range services {
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			// Try to resolve as CNAME if it's not an IP, but only if we don't create loops.
			if q.Name == dns.Fqdn(serv.Host) {
				// x CNAME x is a direct loop, don't add those
				continue
			}

			newRecord := serv.NewCNAME(q.Name, dns.Fqdn(serv.Host))
			if len(previousRecords) > 7 {
				logger.Infof("CNAME lookup limit of 8 exceeded for %s", newRecord)
				// don't add it, and just continue
				continue
			}
			if self.isDuplicateCNAME(newRecord, previousRecords) {
				logger.Infof("CNAME loop detected for record %s", newRecord)
				continue
			}

			nextRecords, err := self.AddressRecords(dns.Question{Name: dns.Fqdn(serv.Host), Qtype: q.Qtype, Qclass: q.Qclass},
				strings.ToLower(dns.Fqdn(serv.Host)), append(previousRecords, newRecord), bufsize, dnssec, both)
			if err == nil {
				// Only have we found something we should add the CNAME and the IP addresses.
				if len(nextRecords) > 0 {
					records = append(records, newRecord)
					records = append(records, nextRecords...)
				}
				continue
			}
			// This means we can not complete the CNAME, try to look else where.
			target := newRecord.Target
			if self.isSubDomain(target) {
				// We should already have found it
				continue
			}
			m1, e1 := self.Lookup(target, q.Qtype, bufsize, dnssec)
			if e1 != nil {
				logger.Errorf("incomplete CNAME chain: %s", e1.Error())
				continue
			}
			// Len(m1.Answer) > 0 here is well?
			records = append(records, newRecord)
			records = append(records, m1.Answer...)
			continue
		case ip.To4() != nil && (q.Qtype == dns.TypeA || both):
			records = append(records, serv.NewA(q.Name, ip.To4()))
		case ip.To4() == nil && (q.Qtype == dns.TypeAAAA || both):
			records = append(records, serv.NewAAAA(q.Name, ip.To16()))
		}
	}
	self.RoundRobin(records)
	return records, nil
}

func (self *Server) TXTRecords(q dns.Question, name string) (records []dns.RR, err error) {
	services, err := self.backend.Records(name, false)
	if err != nil {
		return nil, err
	}

	services = msg.Group(services)

	for _, serv := range services {
		if serv.Text == "" {
			continue
		}
		records = append(records, serv.NewTXT(q.Name))
	}
	return records, nil
}

func (self *Server) CNAMERecords(q dns.Question, name string) (records []dns.RR, err error) {
	services, err := self.backend.Records(name, true)
	if err != nil {
		return nil, err
	}

	services = msg.Group(services)

	if len(services) > 0 {
		serv := services[0]
		if ip := net.ParseIP(serv.Host); ip == nil {
			records = append(records, serv.NewCNAME(q.Name, dns.Fqdn(serv.Host)))
		}
	}
	return records, nil
}

func (self *Server) MXRecords(q dns.Question, name string, bufsize uint16, dnssec bool) (records []dns.RR, extra []dns.RR, err error) {
	services, err := self.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	lookup := make(map[string]bool)
	for _, serv := range services {
		if !serv.Mail {
			continue
		}
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			mx := serv.NewMX(q.Name)
			records = append(records, mx)
			if _, ok := lookup[mx.Mx]; ok {
				break
			}

			lookup[mx.Mx] = true
			if !self.isSubDomain(mx.Mx) {
				m1, e1 := self.Lookup(mx.Mx, dns.TypeA, bufsize, dnssec)
				if e1 == nil {
					extra = append(extra, m1.Answer...)
				}
				m1, e1 = self.Lookup(mx.Mx, dns.TypeAAAA, bufsize, dnssec)
				if e1 == nil {
					// If we have seen CNAME's we *assume* that they are already added.
					for _, a := range m1.Answer {
						if _, ok := a.(*dns.CNAME); !ok {
							extra = append(extra, a)
						}
					}
				}
				break
			}
			// Internal name
			addr, e1 := self.AddressRecords(dns.Question{mx.Mx, dns.ClassINET, dns.TypeA},
				mx.Mx, nil, bufsize, dnssec, true)
			if e1 == nil {
				extra = append(extra, addr...)
			}
		case ip.To4() != nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewMX(q.Name))
			extra = append(extra, serv.NewA(serv.Host, ip.To4()))
		case ip.To4() == nil:
			serv.Host = msg.Domain(serv.Key)
			records = append(records, serv.NewMX(q.Name))
			extra = append(extra, serv.NewAAAA(serv.Host, ip.To16()))
		}
	}
	return records, extra, nil
}

func (self *Server) SRVRecords(q dns.Question, name string, bufsize uint16, dnssec bool) (records []dns.RR, extra []dns.RR, err error) {
	services, err := self.backend.Records(name, false)
	if err != nil {
		return nil, nil, err
	}

	services = msg.Group(services)

	// Looping twice to get the right weight vs priority
	w := make(map[int]int)
	for _, serv := range services {
		weight := 100
		if serv.Weight != 0 {
			weight = serv.Weight
		}
		if _, ok := w[serv.Priority]; !ok {
			w[serv.Priority] = weight
			continue
		}
		w[serv.Priority] += weight
	}
	lookup := make(map[string]bool)
	for _, serv := range services {
		w1 := 100.0 / float64(w[serv.Priority])
		if serv.Weight == 0 {
			w1 *= 100
		} else {
			w1 *= float64(serv.Weight)
		}
		weight := uint16(math.Floor(w1))
		ip := net.ParseIP(serv.Host)
		switch {
		case ip == nil:
			srv := serv.NewSRV(q.Name, weight)
			records = append(records, srv)

			if _, ok := lookup[srv.Target]; ok {
				break
			}

			lookup[srv.Target] = true

			if !self.isSubDomain(srv.Target) {
				m1, e1 := self.Lookup(srv.Target, dns.TypeA, bufsize, dnssec)
				if e1 == nil {
					extra = append(extra, m1.Answer...)
				}
				m1, e1 = self.Lookup(srv.Target, dns.TypeAAAA, bufsize, dnssec)
				if e1 == nil {
					// If we have seen CNAME's we *assume* that they are already added.
					for _, a := range m1.Answer {
						if _, ok := a.(*dns.CNAME); !ok {
							extra = append(extra, a)
						}
					}
				}
				break
			}
			// Internal name, we should have some info on them, either v4 or v6
			// Clients expect a complete answer, because we are a recursor in their
			// view.
			addr, e1 := self.AddressRecords(dns.Question{srv.Target, dns.ClassINET, dns.TypeA},
				srv.Target, nil, bufsize, dnssec, true)
			if e1 == nil {
				extra = append(extra, addr...)
			}
		case ip.To4() != nil:
			serv.Host = msg.Domain(serv.Key)
			srv := serv.NewSRV(q.Name, weight)

			records = append(records, srv)
			extra = append(extra, serv.NewA(srv.Target, ip.To4()))
		case ip.To4() == nil:
			serv.Host = msg.Domain(serv.Key)
			srv := serv.NewSRV(q.Name, weight)

			records = append(records, srv)
			extra = append(extra, serv.NewAAAA(srv.Target, ip.To16()))
		}
	}
	return records, extra, nil
}

func (self *Server) isDuplicateCNAME(r *dns.CNAME, records []dns.RR) bool {
	for _, rec := range records {
		if v, ok := rec.(*dns.CNAME); ok {
			if v.Target == r.Target {
				return true
			}
		}
	}
	return false
}

func (self *Server) NameError(m, req *dns.Msg, name string) {
	m.SetRcode(req, dns.RcodeNameError)
	m.Ns = []dns.RR{self.NewSOA(name)}
	m.Ns[0].Header().Ttl = self.config.MinTtl

}

func (self *Server) isSubDomain(m string) bool {
	for _, domain := range self.config.Domain {
		if dns.IsSubDomain(domain, m) {
			return true
		}
	}
	return false

}
func (self *Server) PTRRecords(q dns.Question) (records []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	serv, err := self.backend.ReverseRecord(name)
	if err != nil {
		return nil, err
	}

	records = append(records, serv.NewPTR(q.Name, serv.Ttl))
	return records, nil
}

func isEtcdNameError(err error, s *Server) bool {
	if e, ok := err.(*etcd.EtcdError); ok {
		if e.ErrorCode == 100 {
			return true
		}
	}
	if err != nil {
		logger.Errorf("error from backend: %s", err.Error())
	}
	return false
}

func appendDomain(s1, s2 string) string {
	if len(s2) > 0 && s2[0] == '.' {
		return s1 + s2
	}
	return s1 + "." + s2
}
