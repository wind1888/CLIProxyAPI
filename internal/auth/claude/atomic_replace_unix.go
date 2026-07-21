//go:build !windows

package claude

import "os"

func atomicReplaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
