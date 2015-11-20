package config

import (
	"net"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
)

const (
	SCacheCapacity = 10000
	RCacheCapacity = 100000
	RCacheTtl      = 60
)

type Config struct {
	// The ip:port SkyDNS should be listening on for incoming DNS requests.
	DnsAddr string `json:"dns_addr,omitempty"`
	// bind to port(s) activated by systemd. If set to true, this overrides DnsAddr.
	Systemd bool `json:"systemd,omitempty"`
	// The domain SkyDNS is authoritative for, defaults to skydns.local.
	Domain []string `json:"domain,omitempty"`
	// Domain pointing to a key where service info is stored when being queried
	// for local.dns.skydns.local.
	Local string `json:"local,omitempty"`
	// The hostmaster responsible for this domain, defaults to hostmaster.<Domain>.
	Hostmaster string `json:"hostmaster,omitempty"`
	DNSSEC     string `json:"dnssec,omitempty"`
	// Round robin A/AAAA replies. Default is true.
	RoundRobin bool `json:"round_robin,omitempty"`
	// Round robin selection of nameservers from among those listed, rather than have all forwarded requests try the first listed server first every time.
	NSRotate bool `json:"ns_rotate,omitempty"`
	// List of ip:port, seperated by commas of recursive nameservers to forward queries to.
	Nameservers []string `json:"nameservers,omitempty"`
	// Never provide a recursive service.
	NoRec       bool          `json:"no_rec,omitempty"`
	ReadTimeout time.Duration `json:"read_timeout,omitempty"`
	// Default priority on SRV records when none is given. Defaults to 10.
	Priority uint16 `json:"priority"`
	// Default TTL, in seconds, when none is given in etcd. Defaults to 3600.
	Ttl uint32 `json:"ttl,omitempty"`
	// Minimum TTL, in seconds, for NXDOMAIN responses. Defaults to 300.
	MinTtl uint32 `json:"min_ttl,omitempty"`
	// SCache, capacity of the signature cache in signatures stored.
	SCache int `json:"scache,omitempty"`
	// RCache, capacity of response cache in resource records stored.
	RCache int `json:"rcache,omitempty"`
	// RCacheTtl, how long to cache in seconds.
	RCacheTtl int `json:"rcache_ttl,omitempty"`
	// How many labels a name should have before we allow forwarding. Default to 2.
	Ndots int `json:"ndot,omitempty"`

	Verbose bool `json:"-"`
	Ipfile  string
	Pidfile string
	// some predefined string "constants"
	LocalDomain []string // "local.dns." + config.Domain
	DnsDomain   []string // "ns.dns". + config.Domain

	// Stub zones support. Pointer to a map that we refresh when we see
	// an update. Map contains domainname -> nameserver:port
}

func SetDefaults(config *Config) error {
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 2 * time.Second
	}
	if config.DnsAddr == "" {
		config.DnsAddr = "0.0.0.0:53"
	}
	if len(config.Domain) == 0 {
		config.Domain = append(config.Domain, "skydns.local.")
	}
	if config.Hostmaster == "" {
		config.Hostmaster = appendDomain("hostmaster", config.Domain[0])
	}
	// People probably don't know that SOA's email addresses cannot
	// contain @-signs, replace them with dots
	config.Hostmaster = dns.Fqdn(strings.Replace(config.Hostmaster, "@", ".", -1))
	if config.MinTtl == 0 {
		config.MinTtl = 60
	}
	if config.Ttl == 0 {
		config.Ttl = 3600
	}
	if config.Priority == 0 {
		config.Priority = 10
	}
	if config.RCache < 0 {
		config.RCache = 0
	}
	if config.SCache < 0 {
		config.SCache = 0
	}
	if config.RCacheTtl == 0 {
		config.RCacheTtl = RCacheTtl
	}
	if config.Ndots <= 0 {
		config.Ndots = 2
	}

	if len(config.Nameservers) == 0 {
		c, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if !os.IsNotExist(err) {
			if err != nil {
				return err
			}
			for _, s := range c.Servers {
				config.Nameservers = append(config.Nameservers, net.JoinHostPort(s, c.Port))
			}
		}
	}
	var tmp []string
	for _, domain := range config.Domain {
		tmp = append(tmp, dns.Fqdn(strings.ToLower(domain)))
	}
	config.Domain = tmp
	for _, domain := range config.Domain {
		config.LocalDomain = append(config.LocalDomain, appendDomain("local.dns", domain))
		config.DnsDomain = append(config.DnsDomain, appendDomain("ns.dns", domain))
	}
	return nil
}

func LoadConfig(conffile string) (*Config, error) {
	config, err := LoadConfigFile(conffile)
	SetDefaults(config)
	return config, err

}

func LoadConfigFile(file string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(file, &config); err != nil {
		return &config, err
	}
	return &config, nil

}

func appendDomain(s1, s2 string) string {
	if len(s2) > 0 && s2[0] == '.' {
		return s1 + s2
	}
	return s1 + "." + s2
}
