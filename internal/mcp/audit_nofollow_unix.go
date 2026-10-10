//go:build !windows

package mcp

import "syscall"

// oNoFollow makes the audit open fail on a symlink.
const oNoFollow = syscall.O_NOFOLLOW
