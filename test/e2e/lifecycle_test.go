//go:build e2e

package e2e

import (
	"strings"
	"testing"
	"time"
)

// unchanged checks that nothing was re-issued, NV holds the certificates from boot (where the image can read it), and the agent re-attests with the same key.
func unchanged(t *testing.T, a *instance, nv, key string, issued int) {
	t.Helper()
	if a.OS.tpmTools {
		if got := a.nvFingerprint(t); got != nv {
			t.Fatalf("NV certificates changed: %s -> %s", nv, got)
		}
	}
	if n := len(issuances(t, a.ID)); n != issued {
		t.Fatalf("%d issuances, want %d", n, issued)
	}
	a.reattest(t, 3*time.Minute)
	if got := keySelector(t, a.agentID()); got != key {
		t.Fatalf("key selector changed: %s -> %s", key, got)
	}
}

// Ensures stop and start and hard reboot of each guest OS keep the vTPM's certificates and the agent re-attests with the certified key.
func TestLifecycle(t *testing.T) {
	forEachGuest(t, func(t *testing.T, g *guestOS) {
		a := g.attested(t, "lifecycle-"+g.name)
		var nv string
		if g.tpmTools {
			nv = a.nvFingerprint(t)
		}
		key, issued := keySelector(t, a.agentID()), len(issuances(t, a.ID))

		// Ensures a stop and start keeps the certificates and the agent re-attests.
		t.Run("stop-start", func(t *testing.T) {
			stopServer(t, a.ID, a.Scope)
			startServer(t, a.ID, a.Scope)
			a.waitSSH(t, 5*time.Minute)
			unchanged(t, a, nv, key, issued)
		})
		// Ensures a hard reboot keeps the certificates and the agent re-attests.
		t.Run("hard-reboot", func(t *testing.T) {
			hardReboot(t, a.ID)
			a.waitSSH(t, 5*time.Minute)
			unchanged(t, a, nv, key, issued)
		})
	})
}

// Ensures an instance booted from a snapshot is certified with a vTPM and key of its own.
func TestSnapshot(t *testing.T) {
	a := attested(t, "snapshot-source")
	image := snapshot(t, a.ID, a.Scope, "e2e-snapshot")
	t.Cleanup(func() { _, _ = cli(adminScope, "image", "delete", image) })
	s := boot(t, "snapshot", bootSpec{image: image, agent: lab.TenantServer.Container, fip: true, wait: true})
	if n := len(issuances(t, s.ID)); n != 1 {
		t.Fatalf("%d issuances for the snapshot instance, want 1", n)
	}
	// The image already has the agent, so the playbook runs again and changes nothing.
	s.waitAttested(t, 10*time.Minute)
	keyA, keyS := keySelector(t, a.agentID()), keySelector(t, s.agentID())
	if keyA == "" || keyA == keyS {
		t.Fatalf("key selectors source %q, snapshot %q", keyA, keyS)
	}
}

// Ensures a resize adds a certified vTPM to a running or stopped instance and removes it again.
func TestResizeVTPM(t *testing.T) {
	// added checks one issuance for event, with the claims a build would carry, and that the agent attests.
	added := func(t *testing.T, i *instance, event string) {
		t.Helper()
		i.waitSSH(t, 3*time.Minute)
		i.waitAttested(t, 5*time.Minute)
		is := issuances(t, i.ID)
		if len(is) != 1 || is[0].Event != event {
			t.Fatalf("issuances %+v, want one for %s", is, event)
		}
		if want, _ := i.verifiedClaims(t); is[0].Claims != want.URI() {
			t.Fatalf("issuer logged %s, want %s", is[0].Claims, want.URI())
		}
	}
	noTPM := func(t *testing.T, i *instance) {
		t.Helper()
		if out, err := i.guestRun("test -e /dev/tpmrm0"); err == nil {
			t.Fatalf("%s has a TPM: %s", i.Name, out)
		}
	}

	// Ensures a running instance gains and loses a vTPM by resize.
	t.Run("running", func(t *testing.T) {
		p := boot(t, "resize", bootSpec{flavor: lab.PlainFlavor, agent: lab.TenantServer.Container, fip: true, wait: true})
		p.bootstrapped(t)
		noTPM(t, p)
		if n := len(issuances(t, p.ID)); n != 0 {
			t.Fatalf("%d issuances without a vTPM", n)
		}

		resize(t, p.ID, p.Scope, lab.Linux.Flavor)
		added(t, p, "resize")
		t.Logf("added, NV %s", p.nvFingerprint(t))

		// Resizing back removes the vTPM and its state; the cleanup removes the libvirt secret Nova leaves.
		t.Cleanup(func() { dropLibvirtSecret(t, p.ID) })
		resize(t, p.ID, p.Scope, lab.PlainFlavor)
		p.bootstrapped(t)
		noTPM(t, p)
		if swtpmState(t, p.ID) {
			t.Fatal("swtpm state left on compute-1")
		}
		if n := len(issuances(t, p.ID)); n != 1 {
			t.Fatalf("%d issuances after the removal, want 1", n)
		}
	})

	// Ensures a stopped instance resized to a vTPM flavor is certified at its first start.
	t.Run("stopped", func(t *testing.T) {
		s := boot(t, "resize-stopped", bootSpec{flavor: lab.PlainFlavor, agent: lab.TenantServer.Container, fip: true, wait: true})
		s.bootstrapped(t)
		stopServer(t, s.ID, s.Scope)
		resize(t, s.ID, s.Scope, lab.Linux.Flavor)
		// Nova does not start the guest, so libvirt has not created the vTPM.
		if n := len(issuances(t, s.ID)); n != 0 {
			t.Fatalf("%d issuances before the first start", n)
		}
		startServer(t, s.ID, s.Scope)
		added(t, s, "first-start-after-resize")
	})
}

// dropLibvirtSecret removes an instance's vTPM secret from compute-1's libvirt.
func dropLibvirtSecret(t testing.TB, uuid string) {
	t.Helper()
	script := `virsh secret-list | awk '$2 == "vtpm" && $3 == "` + uuid + `" {print $1}' | xargs -r -n1 virsh secret-undefine`
	if out, err := nodeRun(lab.Controller, "docker", "exec", "nova_libvirt", "sh", "-c", script); err != nil {
		t.Errorf("drop libvirt secret of %s: %v: %s", uuid, err, out)
	} else if strings.TrimSpace(out) != "" {
		t.Log(strings.TrimSpace(out))
	}
}
