//go:build windows

package mcp

// oNoFollow: Windows has no O_NOFOLLOW; openAudit's Lstat check refuses symlinks.
const oNoFollow = 0
