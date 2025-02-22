// Copyright 2020 retinadata
// Changes in 2025 by Pep Pla
// Licensed under the Apache License, Version 2.0 (the "License");

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/j-keck/arping"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go.etcd.io/etcd/clientv3"
	"go.etcd.io/etcd/clientv3/concurrency"
	"go.etcd.io/etcd/pkg/transport"
)

var (
	Version     = "Not defined"
	version     = flag.Bool("version", false, "Print version and exit")
	prefix      = flag.String("name", "/govip/", "Position to synchronize multiple govips")
	member      = flag.String("member", "hostname", "Unique name for this govip")
	vip         = flag.String("vip", "192.168.0.254/32", "VIP to announce from the selected govip")
	vif         = flag.String("vif", "eth0", "Interface to announce the VIP from")
	etcdaddress = flag.String("etcd", "https://127.0.0.1:2379", "etcd address(es)")
	cafile      = flag.String("cacert", "ca.crt", "etcd CA cert")
	certfile    = flag.String("cert", "server.crt", "etcd cert file")
	keyfile     = flag.String("key", "server.key", "etcd key file")
)

// Check if another machine is already using the VIP (split-brain detection)
func isVIPActive() bool {
	conn, err := net.DialTimeout("tcp", (*vip)+":80", 2*time.Second) // Adjust port if needed
	if err == nil {
		conn.Close()
		log.Warn("VIP already in use on another machine! Split-brain detected.")
		return true
	}
	return false
}

// Ensure that no stale VIP is assigned before starting election
func cleanupStaleVIP() {
	set, vaddr, vlink, _ := hasIP()
	if set {
		log.Warn("Stale VIP detected! Releasing it before election.")
		netlink.AddrDel(vlink, vaddr)
	}
}

// Check if this node currently holds the VIP
func hasIP() (bool, *netlink.Addr, netlink.Link, error) {
	vaddr, err := netlink.ParseAddr(*vip)
	if err != nil {
		return false, nil, nil, err
	}
	vlink, err := netlink.LinkByName(*vif)
	if err != nil {
		return false, nil, nil, err
	}
	addrs, err := netlink.AddrList(vlink, netlink.FAMILY_ALL)
	if err != nil {
		return false, nil, nil, err
	}

	for _, addr := range addrs {
		if vaddr.Equal(addr) {
			return true, vaddr, vlink, nil
		}
	}
	return false, vaddr, vlink, nil
}

// Release the VIP when stepping down as leader
func releaseIP() error {
	log.Debug("Releasing IP address")
	set, vaddr, vlink, err := hasIP()
	if err != nil {
		return err
	}
	if !set {
		log.Debug("IP address not found")
		return nil
	}
	if err := netlink.AddrDel(vlink, vaddr); err != nil {
		return err
	}
	log.Info("IP address released")
	return nil
}

// Assign VIP and send ARP announcements
func ensureIP() (bool, error) {
	log.Debug("Ensuring IP address")
	if isVIPActive() { // Split-brain detection before assigning VIP
		return false, fmt.Errorf("VIP already active on another machine")
	}

	set, vaddr, vlink, err := hasIP()
	if err != nil {
		return false, err
	}
	if set {
		log.Debug("IP address already set")
		return false, nil
	}

	if err := netlink.AddrAdd(vlink, vaddr); err != nil {
		return false, err
	}

	log.Info("VIP assigned! Sending Gratuitous ARPs for faster propagation.")
	for i := 0; i < 10; i++ { // Increase ARP frequency
		arping.GratuitousArpOverIfaceByName(vaddr.IP, *vif)
		time.Sleep(500 * time.Millisecond)
	}

	return true, nil
}

// Monitor etcd leadership state
func verifyLeadership(e *concurrency.Election) {
	res, err := e.Leader(context.Background())
	if err != nil || string(res.Kvs[0].Value) != *member {
		log.Warn("Lost etcd leadership! Releasing VIP.")
		releaseIP()
	}
}

// Send alert when failover occurs
func notifyFailover() {
	log.Warn("Failover detected! Notifying external monitoring system.")
	// Send webhook alert
	http.Post("https://monitoring.example.com/webhook", "application/json",
		strings.NewReader(`{"event": "VIP failover detected"}`))
}

func main() {
	flag.Parse()
	if *version {
		fmt.Println(Version)
		return
	}

	log.SetOutput(os.Stdout) // Log to stdout for debugging
	file, err := os.OpenFile("/var/log/govip.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	log.SetOutput(file) // Log leadership transitions

	cleanupStaleVIP() // New: Ensure VIP is clean before election

	tlsInfo := transport.TLSInfo{
		CertFile:      *certfile,
		KeyFile:       *keyfile,
		TrustedCAFile: *cafile,
	}
	tlsConfig, err := tlsInfo.ClientConfig()
	if err != nil {
		log.Fatal(err)
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   strings.Split(*etcdaddress, ","),
		DialTimeout: 5 * time.Second,
		TLS:         tlsConfig,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithCancel(context.Background())
	s, err := concurrency.NewSession(cli)
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	e := concurrency.NewElection(s, *prefix)

	for {
		select {
		case <-time.After(5 * time.Second):
			log.Debug("Waiting to become the leader")
			err := e.Campaign(ctx, *member)
			if err == context.Canceled {
				return
			}
			if err != nil {
				log.Fatal(err)
			}

			log.Infof("New leader elected: %s", *member)
			time.Sleep(5 * time.Second) // Delay to prevent VIP flapping

			if res, err := ensureIP(); err == nil && res {
				defer releaseIP()
				notifyFailover()
			}

			verifyLeadership(e) // Verify election health periodically
		}
	}
}
