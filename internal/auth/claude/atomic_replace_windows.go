//go:build windows

package claude

import "golang.org/x/sys/windows"

func atomicReplaceFile(source, destination string) error {
	return windows.Rename(source, destination)
}
