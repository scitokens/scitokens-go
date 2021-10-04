package scitokens

import (
	"path"
	"strings"
)

// Scope represents a token authorization scope, with optional path.
type Scope struct {
	Auth string
	Path string
}

// ParseScope parses a scope string like AUTHZ[:PATH].
func ParseScope(s string) Scope {
	pts := strings.SplitN(s, ":", 2)
	if len(pts) == 1 {
		return Scope{pts[0], ""}
	}
	return Scope{pts[0], path.Clean(pts[1])}
}

// String returns the string representation of the scope.
func (s Scope) String() string {
	if s.Path != "" {
		return s.Auth + ":" + s.Path
	}
	return s.Auth
}

// Allowed returns true if operation on resource (can be empty string) is
// allowed by this scope. If resource is a sub-path under the scope's path then
// it is allowed, e.g. if the scope path is write:/baz then operation=write and
// path=/baz/qux is allowed.
func (s Scope) Allowed(operation string, resource string) bool {
	// Normalize resource paths. NB: "If the result of this process is an empty
	// string, Clean returns the string "."."
	r := path.Clean(resource)
	p := path.Clean(s.Path)
	return s.Auth == operation && (p == "." || strings.HasPrefix(r, p))
}
