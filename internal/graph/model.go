package graph

type NodeType string

const (
	NodeProcess NodeType = "process"
	NodePort    NodeType = "port"
)

type EdgeType string

const (
	EdgeConnectsTo EdgeType = "CONNECTS_TO"
	EdgeListensOn  EdgeType = "LISTENS_ON"
)

type Node struct {
	ID       string   `json:"id"`
	Type     NodeType `json:"type"`
	PID      int32    `json:"pid,omitempty"`
	ProcName string   `json:"proc_name,omitempty"`
	Cmdline  string   `json:"cmdline,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	LocalIP  string   `json:"local_ip,omitempty"`
	Port     int      `json:"port,omitempty"`
}

type Edge struct {
	From        string   `json:"from"`
	To          string   `json:"to"`
	Type        EdgeType `json:"type"`
	Established int      `json:"established,omitempty"`
	TimeWait    int      `json:"time_wait,omitempty"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

type Dependency struct {
	Client      Node
	Server      Node
	Port        Node
	Established int
	TimeWait    int
}
