package cli

import (
	"reflect"
	"strings"

	"portik/internal/model"
)

// extractConnectionsAny tries to read Report.Connections (slice) without depending on its element type.
func extractConnectionsAny(rep model.Report) []any {
	v := reflect.ValueOf(rep)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	f := v.FieldByName("Connections")
	if !f.IsValid() || f.Kind() != reflect.Slice {
		return nil
	}
	out := make([]any, 0, f.Len())
	for i := 0; i < f.Len(); i++ {
		out = append(out, f.Index(i).Interface())
	}
	return out
}

func connState(c any) string {
	return getStringField(c, "State", "Status")
}

func connRemoteIP(c any) string {
	// common naming variants across implementations
	ip := getStringField(c, "RemoteIP", "PeerIP", "RemoteAddr", "PeerAddr")
	if ip != "" {
		return normalizeIP(ip)
	}
	// sometimes nested addr struct: Remote (with IP)
	if v := getNestedString(c, "Remote", "IP"); v != "" {
		return normalizeIP(v)
	}
	if v := getNestedString(c, "Peer", "IP"); v != "" {
		return normalizeIP(v)
	}
	return ""
}

func connRemotePort(c any) int {
	if p := getIntField(c, "RemotePort", "PeerPort"); p > 0 {
		return p
	}
	if p := getNestedInt(c, "Remote", "Port"); p > 0 {
		return p
	}
	if p := getNestedInt(c, "Peer", "Port"); p > 0 {
		return p
	}
	return 0
}

func getStringField(obj any, names ...string) string {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	for _, n := range names {
		f := v.FieldByName(n)
		if f.IsValid() && f.Kind() == reflect.String {
			return f.String()
		}
	}
	return ""
}

func getIntField(obj any, names ...string) int {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0
	}
	for _, n := range names {
		f := v.FieldByName(n)
		if !f.IsValid() {
			continue
		}
		switch f.Kind() {
		case reflect.Int, reflect.Int32, reflect.Int64:
			return int(f.Int())
		}
	}
	return 0
}

func getNestedString(obj any, field string, nested string) string {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return ""
	}
	f := v.FieldByName(field)
	if !f.IsValid() {
		return ""
	}
	if f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return ""
		}
		f = f.Elem()
	}
	if f.Kind() != reflect.Struct {
		return ""
	}
	n := f.FieldByName(nested)
	if n.IsValid() && n.Kind() == reflect.String {
		return n.String()
	}
	return ""
}

func getNestedInt(obj any, field string, nested string) int {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return 0
	}
	f := v.FieldByName(field)
	if !f.IsValid() {
		return 0
	}
	if f.Kind() == reflect.Pointer {
		if f.IsNil() {
			return 0
		}
		f = f.Elem()
	}
	if f.Kind() != reflect.Struct {
		return 0
	}
	n := f.FieldByName(nested)
	if !n.IsValid() {
		return 0
	}
	switch n.Kind() {
	case reflect.Int, reflect.Int32, reflect.Int64:
		return int(n.Int())
	}
	return 0
}

func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	// handle "ip:port" string forms
	if strings.Contains(s, ":") && strings.Count(s, ":") == 1 && strings.Contains(s, ".") {
		parts := strings.SplitN(s, ":", 2)
		return parts[0]
	}
	// handle "[ipv6]:port"
	if strings.HasPrefix(s, "[") && strings.Contains(s, "]:") {
		parts := strings.SplitN(s[1:], "]:", 2)
		return parts[0]
	}
	// raw ipv6 or ipv4
	return s
}
