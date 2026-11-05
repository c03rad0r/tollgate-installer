package app

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// The router's LAN is a management link, not an internet uplink. A freshly
// flashed router hands the node a default route with a lower metric than the
// node's real Wi-Fi uplink, and because the router has no WAN yet that route
// blackholes every packet. The operator then sees "cannot ping 9.9.9.9" and
// chases the node's Wi-Fi instead of the router's missing uplink.
//
// ensureManagementLinkIsSecondary detects that shape by probing each default
// route over its own interface, then downgrades the management profile to
// never-default + ignore-auto-dns. It never changes a link that still works and
// never downgrades the only default route (that would leave the node with no
// path at all).

type ipRoute struct {
	Dst      string `json:"dst"`
	Gateway  string `json:"gateway"`
	Dev      string `json:"dev"`
	Metric   int    `json:"metric"`
	Protocol string `json:"protocol"`
}

type uplinkOutcome string

const (
	uplinkFixed       uplinkOutcome = "fixed"
	uplinkHealthy     uplinkOutcome = "healthy"
	uplinkNodeOffline uplinkOutcome = "node_offline"
	uplinkUnavailable uplinkOutcome = "unavailable"
)

type uplinkGuardResult struct {
	Outcome           uplinkOutcome `json:"outcome"`
	ManagementDev     string        `json:"management_dev,omitempty"`
	ManagementProfile string        `json:"management_profile,omitempty"`
	InternetDev       string        `json:"internet_dev,omitempty"`
	Reason            string        `json:"reason,omitempty"`
}

type commandRunner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// parseDefaultRoutes keeps only real default routes with a device.
func parseDefaultRoutes(raw []byte) ([]ipRoute, error) {
	var routes []ipRoute
	if err := json.Unmarshal(raw, &routes); err != nil {
		return nil, err
	}
	out := make([]ipRoute, 0, len(routes))
	for _, r := range routes {
		if r.Dst == "default" && r.Dev != "" {
			out = append(out, r)
		}
	}
	return out, nil
}

// parseRouteGetDev returns the device `ip -j route get` chose.
func parseRouteGetDev(raw []byte) (string, error) {
	var routes []ipRoute
	if err := json.Unmarshal(raw, &routes); err != nil {
		return "", err
	}
	for _, r := range routes {
		if r.Dev != "" {
			return r.Dev, nil
		}
	}
	return "", fmt.Errorf("no route to the router")
}

// activeProfileUUID resolves the NetworkManager profile that owns dev. UUIDs,
// not names: duplicate display names are legal and `connection modify <name>`
// would be ambiguous.
func activeProfileUUID(raw, dev string) string {
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.TrimSpace(parts[1]) == dev {
			return strings.TrimSpace(parts[0])
		}
	}
	return ""
}

// uplinkPlan is the pure decision: downgrade or not, and why.
type uplinkPlan struct {
	Downgrade bool
	Outcome   uplinkOutcome
	Reason    string
	OtherDev  string
}

func planUplinkGuard(mgmt string, defaults []ipRoute, mgmtOK, otherOK bool) uplinkPlan {
	if mgmt == "" {
		return uplinkPlan{Outcome: uplinkUnavailable, Reason: "no route to the router"}
	}
	otherDev := ""
	for _, r := range defaults {
		if r.Dev != "" && r.Dev != mgmt {
			otherDev = r.Dev
			break
		}
	}
	if otherDev == "" {
		return uplinkPlan{
			Outcome: uplinkNodeOffline,
			Reason:  "the router link is the node's only default route",
		}
	}
	if mgmtOK {
		return uplinkPlan{Outcome: uplinkHealthy, OtherDev: otherDev}
	}
	if otherOK {
		return uplinkPlan{Downgrade: true, Outcome: uplinkFixed, OtherDev: otherDev}
	}
	return uplinkPlan{
		Outcome:  uplinkNodeOffline,
		Reason:   "no default route has internet",
		OtherDev: otherDev,
	}
}

// probeOverInterface tests one default route without touching the others.
// TCP/TLS against a fixed IP, not ICMP: ICMP is commonly filtered, which would
// misclassify a healthy link.
func probeOverInterface(dev string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "curl", "-k", "-sS",
		"--interface", dev, "--connect-timeout", "3",
		"-o", "/dev/null", "-w", "%{http_code}", "https://1.1.1.1").Output()
	if err != nil {
		return false
	}
	code, _ := strconv.Atoi(strings.TrimSpace(string(out)))
	return code > 0
}

func ensureManagementLinkIsSecondary(routerIP string) uplinkGuardResult {
	return ensureManagementLinkIsSecondaryWith(execRunner, probeOverInterface, routerIP)
}

func ensureManagementLinkIsSecondaryWith(
	run commandRunner,
	probe func(string) bool,
	routerIP string,
) uplinkGuardResult {
	res := uplinkGuardResult{Outcome: uplinkUnavailable}
	if strings.TrimSpace(routerIP) == "" {
		res.Reason = "router IP is empty"
		return res
	}

	getRaw, err := run("ip", "-j", "route", "get", routerIP)
	if err != nil {
		res.Reason = "ip route get: " + err.Error()
		return res
	}
	mgmt, err := parseRouteGetDev(getRaw)
	if err != nil {
		res.Reason = err.Error()
		return res
	}
	res.ManagementDev = mgmt

	defRaw, err := run("ip", "-j", "route", "show", "default")
	if err != nil {
		res.Reason = "ip route show default: " + err.Error()
		return res
	}
	defaults, err := parseDefaultRoutes(defRaw)
	if err != nil {
		res.Reason = "parse default routes: " + err.Error()
		return res
	}

	otherDev := ""
	for _, r := range defaults {
		if r.Dev != mgmt {
			otherDev = r.Dev
			break
		}
	}
	mgmtOK := probe(mgmt)
	otherOK := otherDev != "" && probe(otherDev)
	plan := planUplinkGuard(mgmt, defaults, mgmtOK, otherOK)
	res.Outcome = plan.Outcome
	res.InternetDev = plan.OtherDev
	res.Reason = plan.Reason
	if !plan.Downgrade {
		return res
	}

	activeRaw, err := run("nmcli", "-t", "-f", "UUID,DEVICE", "connection", "show", "--active")
	if err != nil {
		res.Outcome = uplinkUnavailable
		res.Reason = "nmcli active profiles: " + err.Error()
		return res
	}
	uuid := activeProfileUUID(string(activeRaw), mgmt)
	if uuid == "" {
		res.Outcome = uplinkUnavailable
		res.Reason = "no active NetworkManager profile for " + mgmt
		return res
	}
	res.ManagementProfile = uuid

	if _, err := run("nmcli", "connection", "modify", uuid,
		"ipv4.never-default", "yes", "ipv4.ignore-auto-dns", "yes"); err != nil {
		res.Outcome = uplinkUnavailable
		res.Reason = "nmcli modify: " + err.Error()
		return res
	}
	if _, err := run("nmcli", "device", "reapply", mgmt); err != nil {
		res.Outcome = uplinkUnavailable
		res.Reason = "nmcli reapply: " + err.Error()
		return res
	}
	res.Outcome = uplinkFixed
	return res
}

// ensureNodeInternetForRouter is the call-site wrapper: log the decision, never
// fail the caller. The guard is a repair, not a gate.
func ensureNodeInternetForRouter(routerIP, where string) uplinkGuardResult {
	res := ensureManagementLinkIsSecondary(routerIP)
	log.Printf("uplink-guard %s: outcome=%s mgmt=%s internet=%s profile=%s reason=%s",
		where, res.Outcome, res.ManagementDev, res.InternetDev,
		res.ManagementProfile, res.Reason)
	return res
}
