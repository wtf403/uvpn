package tunnel

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The ruleset is only ever loaded by a privileged process, so a syntax error
// cannot be caught by the unit tests; it surfaces as a failed tunnel start on
// someone's machine. This runs the real nft parser instead.
//
// It needs a network namespace to talk to netlink, and an unprivileged user
// namespace to own it; both are obtained without root via unshare. Where that
// is unavailable the test skips rather than reporting a pass it did not earn.
func TestRulesetParsesWithRealNFT(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not installed")
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not available; cannot validate ruleset without root")
	}

	dnsTargets = resolvConfTargets()
	f, err := os.CreateTemp(t.TempDir(), "rules-*.nft")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(nftRules("wan0")); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// -c checks without committing; the namespace keeps it off the real system.
	cmd := exec.Command(unshare, "--user", "--map-root-user", "--net", nft, "-c", "-f", f.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("nft rejected the ruleset:\n%s\n\nruleset was:\n%s", out, nftRules("wan0"))
	}
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("nft reported problems:\n%s", out)
	}
}
