package scitokens

import (
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
	return Scope{pts[0], pts[1]}
}

// String returns the string representation of the scope.
func (s Scope) String() string {
	if s.Path != "" {
		return s.Auth + ":" + s.Path
	}
	return s.Auth
}

// Allowed returns true if operation on path (can be empty string) is allowed by
// this scope. If path is a sub-path under the scope's path then it is allowed,
// e.g. if the scope path is write:/baz then operation=write and path=/baz/qux
// is allowed.
func (s Scope) Allowed(operation string, path string) bool {
	return s.Auth == operation && strings.HasPrefix(path, s.Path)
}
