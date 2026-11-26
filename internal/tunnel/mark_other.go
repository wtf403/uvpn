//go:build !linux

package tunnel

import "syscall"

// markOutbound is a no-op off Linux. SO_MARK is a Linux-only socket option;
// the full tunnel relies on nftables (Linux) to honor it, and on other
// platforms this package is only here so the binary builds. markingWorks
// will still report whatever the kernel does with a plain socket, and the
// uid-based exemption path applies as it would on Linux.
func markOutbound(_ syscall.RawConn) error { return nil }
