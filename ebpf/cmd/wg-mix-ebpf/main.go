//go:build linux

// Command wgmix-ebpf attaches WireGuard type obfuscation to TC/XDP.
package main

import (
	"flag"
	"fmt"
	"os"

	"wg-mix-ebpf/internal/loader"
	"wg-mix-ebpf/internal/profile"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "attach":
		err = cmdAttach(os.Args[2:])
	case "detach":
		err = cmdDetach(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "wgmix-ebpf: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  wgmix-ebpf attach -iface eth0 -wire X,Y,Z,W [-listen 51820] [-peer 51820] [-xdp native|skb|off] [-pin DIR]
  wgmix-ebpf detach -iface eth0
  wgmix-ebpf status -iface eth0

-wire holds the on-wire types for initiation,response,cookie,transport.
At least one of -listen / -peer is required.
`)
}

func cmdAttach(args []string) error {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	iface := fs.String("iface", "", "network interface")
	listen := fs.String("listen", "", "local WireGuard listen ports, comma separated")
	peer := fs.String("peer", "", "peer WireGuard ports, comma separated")
	wire := fs.String("wire", "", "wire types: init,response,cookie,transport")
	pin := fs.String("pin", "", "bpffs pin dir (default /sys/fs/bpf/wg-mix-ebpf/<iface>)")
	xdp := fs.String("xdp", "native", "XDP mode: native, skb, or off")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" || *wire == "" {
		return fmt.Errorf("-iface and -wire are required")
	}

	p, err := profile.ParseWire(*wire)
	if err != nil {
		return err
	}
	lp, err := profile.ParsePorts(*listen)
	if err != nil {
		return err
	}
	pp, err := profile.ParsePorts(*peer)
	if err != nil {
		return err
	}
	if len(lp) == 0 && len(pp) == 0 {
		return fmt.Errorf("at least one of -listen / -peer is required")
	}

	if err := loader.Attach(loader.Config{
		Iface:       *iface,
		ListenPorts: lp,
		PeerPorts:   pp,
		Wire:        p.Wire,
		PinDir:      *pin,
		XDPMode:     *xdp,
	}); err != nil {
		return err
	}
	fmt.Printf("attached %s: wire=%v xdp=%s\n", *iface, p.Wire, *xdp)
	return nil
}

func cmdDetach(args []string) error {
	fs := flag.NewFlagSet("detach", flag.ContinueOnError)
	iface := fs.String("iface", "", "interface")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return fmt.Errorf("-iface is required")
	}
	if err := loader.Detach(*iface); err != nil {
		return err
	}
	fmt.Printf("detached %s\n", *iface)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	iface := fs.String("iface", "", "interface")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return fmt.Errorf("-iface is required")
	}
	s, err := loader.Status(*iface)
	if err != nil {
		return err
	}
	fmt.Printf("egress: matched=%d rewritten=%d\n", s.Matched, s.Rewritten)
	fmt.Printf("ingress: matched=%d rewritten=%d\n", s.XDPMatched, s.XDPRewritten)
	return nil
}
