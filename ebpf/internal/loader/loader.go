//go:build linux

// Package loader loads the eBPF object and attaches TC egress / XDP ingress.
package loader

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"wg-mix-ebpf/bpf"
)

const (
	roleLocal uint32 = 1
	rolePeer  uint32 = 2

	tcFilterName = "typeobfs"

	// UAPI xdp flags
	xdpFlagsUpdateIfNoExist = 1 << 0
	xdpFlagsSKBMode         = 1 << 1
	xdpFlagsDRVMode         = 1 << 2
)

// Config describes one attachment.
type Config struct {
	Iface       string
	ListenPorts []uint16 // local WireGuard ports
	PeerPorts   []uint16 // peer WireGuard ports
	Wire        [4]uint32
	PinDir      string
	XDPMode     string // native (default), skb, off
}

// Stats are the per-CPU counters exposed by the programs.
type Stats struct {
	Matched      uint64
	Rewritten    uint64
	XDPMatched   uint64
	XDPRewritten uint64
}

// defaultPinDir returns the default bpffs directory for an interface.
func defaultPinDir(iface string) string {
	return filepath.Join("/sys/fs/bpf/wg-mix-ebpf", iface)
}

// Attach loads both programs, attaches them, and pins maps for status/detach.
func Attach(cfg Config) error {
	if cfg.Iface == "" {
		return errors.New("iface is required")
	}
	if cfg.PinDir == "" {
		cfg.PinDir = defaultPinDir(cfg.Iface)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpf.Object()))
	if err != nil {
		return fmt.Errorf("parse bpf object: %w", err)
	}
	// Set types explicitly in case the section names are not recognized.
	for name, typ := range map[string]ebpf.ProgramType{
		"typeobfs_egress":  ebpf.SchedCLS,
		"typeobfs_ingress": ebpf.XDP,
	} {
		if p := spec.Programs[name]; p != nil && p.Type == ebpf.UnspecifiedProgram {
			p.Type = typ
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load bpf collection: %w\n%s", err, strings.Join(ve.Log, "\n"))
		}
		return fmt.Errorf("load bpf collection: %w", err)
	}
	defer coll.Close()

	wireMap := coll.Maps["wire_types"]
	portMap := coll.Maps["ports"]
	if wireMap == nil || portMap == nil {
		return errors.New("bpf maps wire_types/ports missing")
	}
	for i, w := range cfg.Wire {
		if w == 0 {
			return fmt.Errorf("wire[%d] is zero", i)
		}
		if err := wireMap.Put(uint32(i), w); err != nil {
			return fmt.Errorf("wire_types[%d]: %w", i, err)
		}
	}

	roles := make(map[uint16]uint32)
	for _, p := range cfg.ListenPorts {
		roles[p] |= roleLocal
	}
	for _, p := range cfg.PeerPorts {
		roles[p] |= rolePeer
	}
	if len(roles) == 0 {
		return errors.New("at least one listen or peer port is required")
	}
	for p, r := range roles {
		if err := portMap.Put(uint32(p), r); err != nil {
			return fmt.Errorf("ports[%d]: %w", p, err)
		}
	}

	link, err := netlink.LinkByName(cfg.Iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", cfg.Iface, err)
	}
	if err := checkNotAttached(link); err != nil {
		return err
	}
	if err := ensureClsact(link.Attrs().Index); err != nil {
		return err
	}

	egress := coll.Programs["typeobfs_egress"]
	ingress := coll.Programs["typeobfs_ingress"]
	if egress == nil || ingress == nil {
		return errors.New("programs typeobfs_egress/typeobfs_ingress missing")
	}
	filter, err := attachFilter(link, egress)
	if err != nil {
		return err
	}

	xdpAttached := false
	if cfg.XDPMode != "off" {
		if err := attachXDP(link, ingress, cfg.XDPMode); err != nil {
			_ = netlink.FilterDel(filter)
			return err
		}
		xdpAttached = true
	}

	cleanup := func() {
		if xdpAttached {
			_ = detachXDP(link)
		}
		_ = netlink.FilterDel(filter)
		_ = os.RemoveAll(cfg.PinDir)
	}

	// Pin after a successful attach so a failure leaves nothing behind.
	// Remove stale pins from a previous crash first; we already checked that
	// no live filter is attached.
	if err := os.RemoveAll(cfg.PinDir); err != nil {
		cleanup()
		return fmt.Errorf("clear pin dir: %w", err)
	}
	if err := os.MkdirAll(cfg.PinDir, 0o755); err != nil {
		cleanup()
		return fmt.Errorf("create pin dir %s (is bpffs mounted? try: mount -t bpf bpf /sys/fs/bpf): %w", cfg.PinDir, err)
	}
	for name, m := range coll.Maps {
		if err := m.Pin(filepath.Join(cfg.PinDir, name)); err != nil {
			cleanup()
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}
	return nil
}

// Detach removes the tc filter, the clsact qdisc (best effort) and pins.
func Detach(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link %s: %w", iface, err)
	}

	// Best effort: remove the XDP program before the TC filter.
	_ = detachXDP(link)

	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("list tc filters: %w", err)
	}
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && bf.Name == tcFilterName {
			if err := netlink.FilterDel(f); err != nil {
				return fmt.Errorf("delete tc filter: %w", err)
			}
		}
	}

	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	_ = netlink.QdiscDel(qdisc) // best effort; may be shared or already gone

	return os.RemoveAll(defaultPinDir(iface))
}

// Status reads the pinned stats map and sums per-CPU counters.
func Status(iface string) (Stats, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(defaultPinDir(iface), "stats"), &ebpf.LoadPinOptions{})
	if err != nil {
		return Stats{}, fmt.Errorf("open stats map: %w", err)
	}
	defer m.Close()

	var s Stats
	out := []*uint64{&s.Matched, &s.Rewritten, &s.XDPMatched, &s.XDPRewritten}
	for i, dst := range out {
		var vals []uint64
		if err := m.Lookup(uint32(i), &vals); err != nil {
			return Stats{}, fmt.Errorf("lookup stats[%d]: %w", i, err)
		}
		for _, v := range vals {
			*dst += v
		}
	}
	return s, nil
}

func ensureClsact(ifindex int) error {
	qdisc := &netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: ifindex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("add clsact qdisc: %w", err)
	}
	return nil
}

func checkNotAttached(link netlink.Link) error {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("list tc filters: %w", err)
	}
	for _, f := range filters {
		if bf, ok := f.(*netlink.BpfFilter); ok && bf.Name == tcFilterName {
			return errors.New("already attached; run detach first")
		}
	}
	if x := link.Attrs().Xdp; x != nil && x.Attached {
		return errors.New("xdp already attached; run detach first")
	}
	return nil
}

func attachFilter(link netlink.Link, prog *ebpf.Program) (*netlink.BpfFilter, error) {
	f := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Priority:  1,
			// host order; netlink swaps it into tcm_info internally
			Protocol: 0x0003, // ETH_P_ALL
		},
		Fd:           prog.FD(),
		Name:         tcFilterName,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(f); err != nil {
		return nil, fmt.Errorf("attach tc filter: %w", err)
	}
	return f, nil
}

func attachXDP(link netlink.Link, prog *ebpf.Program, mode string) error {
	if prog == nil {
		return errors.New("program typeobfs_ingress missing")
	}
	var flags int
	switch mode {
	case "", "native":
		flags = xdpFlagsDRVMode
	case "skb":
		flags = xdpFlagsSKBMode
	default:
		return fmt.Errorf("unknown xdp mode %q (native|skb|off)", mode)
	}
	flags |= xdpFlagsUpdateIfNoExist
	if err := netlink.LinkSetXdpFdWithFlags(link, prog.FD(), flags); err != nil {
		return fmt.Errorf("attach xdp (%s): %w", mode, err)
	}
	return nil
}

func detachXDP(link netlink.Link) error {
	// Detach with the mode that is actually attached (native vs generic),
	// otherwise the kernel may reject the request.
	flags := 0
	if x := link.Attrs().Xdp; x != nil && x.Attached {
		flags = int(x.Flags)
	}
	_ = netlink.LinkSetXdpFdWithFlags(link, -1, flags)

	// Verify: some kernels (observed on WSL/veth generic XDP) report success
	// but only drop the program when the link goes down.
	cur, err := netlink.LinkByName(link.Attrs().Name)
	if err != nil {
		return nil
	}
	x := cur.Attrs().Xdp
	if x == nil || !x.Attached {
		return nil
	}
	wasUp := cur.Attrs().Flags&net.FlagUp != 0
	if wasUp {
		if err := netlink.LinkSetDown(cur); err != nil {
			return err
		}
	}
	err = netlink.LinkSetXdpFdWithFlags(cur, -1, flags)
	if wasUp {
		_ = netlink.LinkSetUp(cur)
	}
	return err
}
