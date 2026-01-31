package graph

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"

	"github.com/pratik-anurag/portik/internal/proc"
	"github.com/pratik-anurag/portik/internal/sockets"
)

type Options struct {
	Ports     []int
	LocalOnly bool
}

type listenerRec struct {
	PID      int32
	ProcName string
	Cmdline  string
	LocalIP  string
	Port     int
	Protocol string
}

type depKey struct {
	clientPID int32
	serverPID int32
	portID    string
}

type procInfo struct {
	pid     int32
	name    string
	cmdline string
}

func Build(proto string, opt Options) (Graph, []Dependency, []string, error) {
	if proto != "tcp" {
		return Graph{}, nil, nil, fmt.Errorf("unsupported proto: %s", proto)
	}

	portsFilter := make(map[int]bool)
	for _, p := range opt.Ports {
		portsFilter[p] = true
	}

	listeners, err := sockets.ListListeners(proto)
	if err != nil {
		return Graph{}, nil, nil, err
	}
	for i := range listeners {
		proc.Enrich(&listeners[i])
	}

	listenerRecs := make([]listenerRec, 0, len(listeners))
	for _, l := range listeners {
		if len(portsFilter) > 0 && !portsFilter[l.LocalPort] {
			continue
		}
		ip := normalizeIP(l.LocalIP)
		listenerRecs = append(listenerRecs, listenerRec{
			PID:      l.PID,
			ProcName: l.ProcName,
			Cmdline:  l.Cmdline,
			LocalIP:  ip,
			Port:     l.LocalPort,
			Protocol: proto,
		})
	}

	conns, err := sockets.ListConnections(proto)
	if err != nil {
		return Graph{}, nil, nil, err
	}

	localIPs := localIPSet()

	nodes := map[string]Node{}
	edges := map[string]Edge{}
	depsMap := map[depKey]*Dependency{}
	warnSet := map[string]bool{}

	addWarn := func(msg string) {
		if msg == "" || warnSet[msg] {
			return
		}
		warnSet[msg] = true
	}

	addNode := func(n Node) {
		if n.ID == "" {
			return
		}
		if _, ok := nodes[n.ID]; ok {
			return
		}
		nodes[n.ID] = n
	}

	addEdge := func(e Edge) {
		key := e.From + "|" + e.To + "|" + string(e.Type)
		if existing, ok := edges[key]; ok {
			existing.Established += e.Established
			existing.TimeWait += e.TimeWait
			edges[key] = existing
			return
		}
		edges[key] = e
	}

	procs := map[int32]procInfo{}
	cacheProc := func(pid int32, nameHint string, cmdHint string) procInfo {
		if pid <= 0 {
			return procInfo{}
		}
		if p, ok := procs[pid]; ok {
			return p
		}
		name := strings.TrimSpace(nameHint)
		cmd := strings.TrimSpace(cmdHint)
		if name == "" || cmd == "" {
			psName, psCmd := psProcess(pid)
			if name == "" {
				name = psName
			}
			if cmd == "" {
				cmd = psCmd
			}
		}
		info := procInfo{pid: pid, name: name, cmdline: truncateCmdline(cmd, 120)}
		procs[pid] = info
		return info
	}

	for _, l := range listenerRecs {
		if l.PID <= 0 {
			addWarn(fmt.Sprintf("listener pid missing for %s:%d", fmtIP(l.LocalIP), l.Port))
			continue
		}
		pi := cacheProc(l.PID, l.ProcName, l.Cmdline)
		pNode := processNode(pi)
		portNode := portNode(proto, l.LocalIP, l.Port)
		addNode(pNode)
		addNode(portNode)
		addEdge(Edge{From: pNode.ID, To: portNode.ID, Type: EdgeListensOn})
	}

	for _, c := range conns {
		state := normalizeState(c.State)
		if state != "ESTABLISHED" && state != "TIME_WAIT" {
			continue
		}
		if len(portsFilter) > 0 && !portsFilter[c.RemotePort] {
			continue
		}
		remoteIP := normalizeIP(c.RemoteIP)
		if remoteIP == "" {
			continue
		}
		if !isLocalIP(remoteIP, localIPs) {
			if opt.LocalOnly {
				continue
			}
			// dependency edges are only created for local listeners
			continue
		}
		match, ambiguous := matchListener(listenerRecs, remoteIP, c.RemotePort)
		if ambiguous {
			addWarn(fmt.Sprintf("multiple listeners for %s:%d; skipping dependency", remoteIP, c.RemotePort))
			continue
		}
		if match == nil {
			continue
		}
		if c.PID <= 0 {
			addWarn(fmt.Sprintf("connection pid missing for %s:%d", remoteIP, c.RemotePort))
			continue
		}
		if match.PID <= 0 {
			addWarn(fmt.Sprintf("listener pid missing for %s:%d", remoteIP, c.RemotePort))
			continue
		}

		clientInfo := cacheProc(c.PID, c.ProcName, "")
		serverInfo := cacheProc(match.PID, match.ProcName, match.Cmdline)

		clientNode := processNode(clientInfo)
		serverNode := processNode(serverInfo)
		portNode := portNode(proto, match.LocalIP, match.Port)

		addNode(clientNode)
		addNode(serverNode)
		addNode(portNode)
		addEdge(Edge{From: serverNode.ID, To: portNode.ID, Type: EdgeListensOn})

		if state == "ESTABLISHED" {
			recordDependency(depsMap, clientNode, serverNode, portNode, true)
			addEdge(Edge{From: clientNode.ID, To: portNode.ID, Type: EdgeConnectsTo, Established: 1})
		} else {
			recordDependency(depsMap, clientNode, serverNode, portNode, false)
			addEdge(Edge{From: clientNode.ID, To: portNode.ID, Type: EdgeConnectsTo, TimeWait: 1})
		}
	}

	graph := Graph{
		Nodes: sortedNodes(nodes),
		Edges: sortedEdges(edges),
	}

	deps := make([]Dependency, 0, len(depsMap))
	for _, d := range depsMap {
		deps = append(deps, *d)
	}
	sortDependencies(deps)

	warns := make([]string, 0, len(warnSet))
	for w := range warnSet {
		warns = append(warns, w)
	}
	sort.Strings(warns)

	return graph, deps, warns, nil
}

func matchListener(listeners []listenerRec, remoteIP string, remotePort int) (*listenerRec, bool) {
	if remotePort <= 0 {
		return nil, false
	}
	remoteIP = normalizeIP(remoteIP)
	var exact []listenerRec
	var wildcard []listenerRec
	for _, l := range listeners {
		if l.Port != remotePort {
			continue
		}
		if ipsEqual(l.LocalIP, remoteIP) {
			exact = append(exact, l)
			continue
		}
		if isWildcardIP(l.LocalIP) {
			wildcard = append(wildcard, l)
		}
	}
	if len(exact) == 1 {
		return &exact[0], false
	}
	if len(exact) > 1 {
		return nil, true
	}
	if len(wildcard) == 1 {
		return &wildcard[0], false
	}
	if len(wildcard) > 1 {
		return nil, true
	}
	return nil, false
}

func normalizeState(state string) string {
	state = strings.ToUpper(strings.TrimSpace(state))
	switch state {
	case "ESTAB":
		return "ESTABLISHED"
	case "TIME-WAIT":
		return "TIME_WAIT"
	default:
		return state
	}
}

func recordDependency(deps map[depKey]*Dependency, client Node, server Node, port Node, established bool) {
	key := depKey{clientPID: client.PID, serverPID: server.PID, portID: port.ID}
	dep := deps[key]
	if dep == nil {
		dep = &Dependency{Client: client, Server: server, Port: port}
		deps[key] = dep
	}
	if established {
		dep.Established++
		return
	}
	dep.TimeWait++
}

func processNode(p procInfo) Node {
	return Node{
		ID:       fmt.Sprintf("proc:%d", p.pid),
		Type:     NodeProcess,
		PID:      p.pid,
		ProcName: p.name,
		Cmdline:  p.cmdline,
	}
}

func portNode(proto, ip string, port int) Node {
	ip = normalizeIP(ip)
	if ip == "" {
		ip = "*"
	}
	return Node{
		ID:       fmt.Sprintf("port:%s:%s:%d", proto, ip, port),
		Type:     NodePort,
		Protocol: proto,
		LocalIP:  ip,
		Port:     port,
	}
}

func sortedNodes(in map[string]Node) []Node {
	out := make([]Node, 0, len(in))
	for _, n := range in {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].ID < out[j].ID
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func sortedEdges(in map[string]Edge) []Edge {
	out := make([]Edge, 0, len(in))
	for _, e := range in {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			if out[i].From == out[j].From {
				return out[i].To < out[j].To
			}
			return out[i].From < out[j].From
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func sortDependencies(deps []Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].Established == deps[j].Established {
			if deps[i].Client.ProcName == deps[j].Client.ProcName {
				if deps[i].Server.ProcName == deps[j].Server.ProcName {
					return deps[i].Port.Port < deps[j].Port.Port
				}
				return deps[i].Server.ProcName < deps[j].Server.ProcName
			}
			return deps[i].Client.ProcName < deps[j].Client.ProcName
		}
		return deps[i].Established > deps[j].Established
	})
}

func TopDependencies(deps []Dependency, n int) []Dependency {
	if n <= 0 || len(deps) <= n {
		return deps
	}
	return deps[:n]
}

func truncateCmdline(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func normalizeIP(ip string) string {
	ip = strings.TrimSpace(ip)
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	if i := strings.Index(ip, "%"); i >= 0 {
		ip = ip[:i]
	}
	if ip == "" {
		return ""
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
		return parsed.String()
	}
	return ip
}

func isWildcardIP(ip string) bool {
	ip = normalizeIP(ip)
	return ip == "" || ip == "0.0.0.0" || ip == "::" || ip == "*"
}

func ipsEqual(a, b string) bool {
	return normalizeIP(a) == normalizeIP(b)
}

func localIPSet() map[string]bool {
	out := map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addr.String()
			if i := strings.Index(ip, "/"); i >= 0 {
				ip = ip[:i]
			}
			ip = normalizeIP(ip)
			if ip != "" {
				out[ip] = true
			}
		}
	}
	return out
}

func isLocalIP(ip string, local map[string]bool) bool {
	ip = normalizeIP(ip)
	if ip == "" {
		return false
	}
	return local[ip]
}

func fmtIP(ip string) string {
	if ip == "" {
		return "*"
	}
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		return "[" + ip + "]"
	}
	return ip
}

func psProcess(pid int32) (string, string) {
	name := psField(pid, "comm=")
	cmd := psField(pid, "command=")
	return strings.TrimSpace(name), strings.TrimSpace(cmd)
}

func psField(pid int32, format string) string {
	cmd := exec.Command("ps", "-p", itoa32(pid), "-o", format)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	_ = cmd.Run()
	return strings.TrimSpace(buf.String())
}

func itoa32(n int32) string {
	if n == 0 {
		return "0"
	}
	x := int(n)
	var b [32]byte
	i := len(b)
	for x > 0 {
		i--
		b[i] = byte('0' + x%10)
		x /= 10
	}
	return string(b[i:])
}
