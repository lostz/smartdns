package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/coreos/go-etcd/etcd"
	"github.com/lostz/logging"
	backendetcd "github.com/lostz/skydns/backends/etcd"
	"github.com/lostz/smartdns/config"
	"github.com/lostz/smartdns/server"
	"github.com/miekg/dns"
)

var logger = logging.GetLogger("main")

func main() {
	conf := resolveConfig()
	if err := start(conf); err != nil {
		os.Exit(1)
	}
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	<-ch
	signal.Stop(ch)

}

func resolveConfig() (conf *config.Config) {
	conffile := flag.String("conf", "smartdns.conf", "Config file path (Configs in this file are over-written by command line options)")
	flag.Parse()
	conf, confErr := config.LoadConfig(*conffile)
	if confErr != nil {
		logger.Criticalf("Failed to load the config file: %s", confErr)
		os.Exit(1)
	}
	return

}

func createPidFile(pidfile string) error {
	if pidString, err := ioutil.ReadFile(pidfile); err == nil {
		if pid, err := strconv.Atoi(string(pidString)); err == nil {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d/", pid)); err == nil {
				return fmt.Errorf("Pidfile found, try stopping another running dolly or delete %s", pidfile)
			} else {
				logger.Warningf("Pidfile found, but there seems no another process of dolly. Ignoring %s", pidfile)
			}
		} else {
			logger.Warningf("Malformed pidfile found. Ignoring %s", pidfile)
		}
	}

	file, err := os.Create(pidfile)
	if err != nil {
		logger.Criticalf("Failed to create a pidfile: %s", err)
		return err
	}
	defer file.Close()

	_, err = fmt.Fprintf(file, "%d", os.Getpid())
	return err
}

func removePidFile(pidfile string) {
	if err := os.Remove(pidfile); err != nil {
		logger.Errorf("Failed to remove the pidfile: %s: %s", pidfile, err)
	}
}

func start(conf *config.Config) error {
	client := newClient("http://127.0.0.1:4001", "", "", "")
	if err := createPidFile(conf.Pidfile); err != nil {
		return err
	}
	if conf.Local != "" {
		conf.Local = dns.Fqdn(conf.Local)
	}

	backend := backendetcd.NewBackend(client, &backendetcd.Config{
		Ttl:      conf.Ttl,
		Priority: conf.Priority,
	})

	s := server.NewServer(backend, conf)
	s.Start()
	return nil

}

func newClient(machine, tlsCert, tlsKey, tlsCACert string) (client *etcd.Client) {
	if strings.HasPrefix(machine, "https://") {
		var err error
		// TODO(miek): machines is local, the rest is global, ugly.
		if client, err = etcd.NewTLSClient([]string{machine}, tlsCert, tlsKey, tlsCACert); err != nil {
			// TODO(miek): would be nice if this wasn't a fatal error
			logger.Errorf("skydns: failure to connect: %s", err)
		}
		return client
	}
	return etcd.NewClient([]string{machine})
}
