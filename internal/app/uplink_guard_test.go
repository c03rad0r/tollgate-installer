package app

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDefaultRoutesKeepsOnlyDefaults(t *testing.T) {
	raw := []byte(`[
		{"dst":"default","gateway":"192.168.1.1","dev":"enx9","metric":100},
		{"dst":"default","gateway":"10.2.0.1","dev":"wlp59s0","metric":600},
		{"dst":"10.2.0.0/16","dev":"wlp59s0"},
		{"dst":"default","dev":""}
	]`)
	routes, err := parseDefaultRoutes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 {
		t.Fatalf("want 2 defaults, got %d: %#v", len(routes), routes)
	}
	if routes[0].Dev != "enx9" || routes[1].Dev != "wlp59s0" {
		t.Fatalf("unexpected devices: %#v", routes)
	}
}

func TestParseRouteGetDev(t *testing.T) {
	dev, err := parseRouteGetDev([]byte(`[{"dst":"192.168.1.1","dev":"enx9c69d3c70689","gateway":"192.168.1.1"}]`))
	if err != nil {
		t.Fatal(err)
	}
	if dev != "enx9c69d3c70689" {
		t.Fatalf("got %q", dev)
	}
	if _, err := parseRouteGetDev([]byte(`[]`)); err == nil {
		t.Fatal("expected an error when no route matches")
	}
}

func TestActiveProfileUUIDMatchesDeviceNotName(t *testing.T) {
	raw := "2be57900-6ad8-3711-b3c2-27a27155dd70:enx9c69d3c70689\n" +
		"fa76e452-23ba-4114-a454-79699077f5dd:wlp59s0\n"
	if got := activeProfileUUID(raw, "enx9c69d3c70689"); got != "2be57900-6ad8-3711-b3c2-27a27155dd70" {
		t.Fatalf("got %q", got)
	}
	if got := activeProfileUUID(raw, "missing0"); got != "" {
		t.Fatalf("want empty for an unknown device, got %q", got)
	}
}

func defaults() []ipRoute {
	return []ipRoute{
		{Dst: "default", Dev: "enx9", Gateway: "192.168.1.1", Metric: 100},
		{Dst: "default", Dev: "wlp59s0", Gateway: "10.2.0.1", Metric: 600},
	}
}

func TestPlanUplinkGuard(t *testing.T) {
	cases := []struct {
		name      string
		mgmt      string
		routes    []ipRoute
		mgmtOK    bool
		otherOK   bool
		downgrade bool
		outcome   uplinkOutcome
	}{
		{"router lan is a black hole", "enx9", defaults(), false, true, true, uplinkFixed},
		{"router already routes", "enx9", defaults(), true, true, false, uplinkHealthy},
		{"only the router link exists", "enx9", defaults()[:1], false, false, false, uplinkNodeOffline},
		{"neither link works", "enx9", defaults(), false, false, false, uplinkNodeOffline},
		{"no management route", "", defaults(), false, true, false, uplinkUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planUplinkGuard(tc.mgmt, tc.routes, tc.mgmtOK, tc.otherOK)
			if got.Downgrade != tc.downgrade {
				t.Fatalf("downgrade=%v want %v (%s)", got.Downgrade, tc.downgrade, got.Reason)
			}
			if got.Outcome != tc.outcome {
				t.Fatalf("outcome=%q want %q (%s)", got.Outcome, tc.outcome, got.Reason)
			}
		})
	}
}

// TestEnsureManagementLinkDowngradesTheWanLessRouter is the regression for the
// X280 case: Wi-Fi works, the router's LAN answers at 192.168.1.1 but has no
// WAN, and its DHCP default (metric 100) beats Wi-Fi (metric 600).
func TestEnsureManagementLinkDowngradesTheWanLessRouter(t *testing.T) {
	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		switch {
		case name == "ip" && strings.Contains(line, "route get"):
			return []byte(`[{"dst":"192.168.1.1","dev":"enx9","gateway":"192.168.1.1"}]`), nil
		case name == "ip" && strings.Contains(line, "show default"):
			return []byte(`[{"dst":"default","dev":"enx9","metric":100},{"dst":"default","dev":"wlp59s0","metric":600}]`), nil
		case name == "nmcli" && strings.Contains(line, "show --active"):
			return []byte("2be57900:enx9\nfa76e452:wlp59s0\n"), nil
		case name == "nmcli":
			return []byte{}, nil
		}
		return nil, errors.New("unexpected command: " + line)
	}
	probe := func(dev string) bool { return dev == "wlp59s0" }

	res := ensureManagementLinkIsSecondaryWith(run, probe, "192.168.1.1")
	if res.Outcome != uplinkFixed {
		t.Fatalf("outcome=%q reason=%s", res.Outcome, res.Reason)
	}
	if res.ManagementDev != "enx9" || res.ManagementProfile != "2be57900" || res.InternetDev != "wlp59s0" {
		t.Fatalf("unexpected result: %#v", res)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "nmcli connection modify 2be57900 ipv4.never-default yes ipv4.ignore-auto-dns yes") {
		t.Fatalf("never-default was not applied:\n%s", joined)
	}
	if !strings.Contains(joined, "nmcli device reapply enx9") {
		t.Fatalf("reapply was not called:\n%s", joined)
	}
}

func TestEnsureManagementLinkLeavesAHealthyRouterAlone(t *testing.T) {
	var modified bool
	run := func(name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case name == "ip" && strings.Contains(line, "route get"):
			return []byte(`[{"dev":"enx9"}]`), nil
		case name == "ip" && strings.Contains(line, "show default"):
			return []byte(`[{"dst":"default","dev":"enx9"},{"dst":"default","dev":"wlp59s0"}]`), nil
		case name == "nmcli":
			modified = true
			return []byte{}, nil
		}
		return nil, errors.New("unexpected command: " + line)
	}
	probe := func(dev string) bool { return true }

	res := ensureManagementLinkIsSecondaryWith(run, probe, "192.168.1.1")
	if res.Outcome != uplinkHealthy {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	if modified {
		t.Fatal("a healthy management link must not be modified")
	}
}

func TestEnsureManagementLinkNeverDowngradesTheOnlyRoute(t *testing.T) {
	var modified bool
	run := func(name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		switch {
		case name == "ip" && strings.Contains(line, "route get"):
			return []byte(`[{"dev":"enx9"}]`), nil
		case name == "ip" && strings.Contains(line, "show default"):
			return []byte(`[{"dst":"default","dev":"enx9"}]`), nil
		case name == "nmcli":
			modified = true
			return []byte{}, nil
		}
		return nil, errors.New("unexpected command: " + line)
	}
	probe := func(string) bool { return false }

	res := ensureManagementLinkIsSecondaryWith(run, probe, "192.168.1.1")
	if res.Outcome != uplinkNodeOffline {
		t.Fatalf("outcome=%q", res.Outcome)
	}
	if modified {
		t.Fatal("the only default route must never be downgraded")
	}
}
