//go:build linux

package tunnel

import "syscall"

// markOutbound sets SO_MARK so nftables can exempt our own sockets from the
// redirect. SO_MARK needs CAP_NET_ADMIN, which the tunnel has because it runs
// as root, but not every context allows it, so a failure here is reported and
// the ruleset falls back to exempting by uid rather than being fatal.
func markOutbound(c syscall.RawConn) error {
	var inner error
	if err := c.Control(func(fd uintptr) {
		inner = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, bypassMark)
	}); err != nil {
		return err
	}
	return inner
}
