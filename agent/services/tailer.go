package services

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	tailReadInterval = 250 * time.Millisecond
	tailReopenWait   = 2 * time.Second
)

// tailer follows a single log file. It tolerates the file not existing
// at startup (the daemon may not be installed yet) and detects rotation
// by watching for truncation or a changed inode.
type tailer struct {
	path string
}

func newTailer(path string) *tailer {
	return &tailer{path: path}
}

// run blocks until ctx is cancelled, calling emit for each newline-
// terminated line that arrives. Each open seeks to EOF, so historical
// lines from base-image bring-up don't surface as live events.
func (t *tailer) run(ctx context.Context, emit func(string)) {
	var (
		file    *os.File
		reader  *bufio.Reader
		lastIno uint64
	)
	defer func() {
		if file != nil {
			file.Close()
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		if file == nil {
			f, err := os.Open(t.path)
			if err != nil {
				if !waitFor(ctx, tailReopenWait) {
					return
				}
				continue
			}
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				f.Close()
				continue
			}
			file = f
			reader = bufio.NewReader(file)
			if ino, ok := inode(file); ok {
				lastIno = ino
			}
		}

		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			emit(strings.TrimRight(line, "\r\n"))
		}
		if err == nil {
			continue
		}

		if !errors.Is(err, io.EOF) {
			log.Printf("services.tailer %s: read: %v", t.path, err)
		}

		if rotated(file, t.path, lastIno) {
			file.Close()
			file, reader = nil, nil
			continue
		}

		if !waitFor(ctx, tailReadInterval) {
			return
		}
	}
}

func inode(f *os.File) (uint64, bool) {
	info, err := f.Stat()
	if err != nil {
		return 0, false
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return sys.Ino, true
}

// rotated checks whether the file we have open still matches the one at
// path. Either truncation (file shorter than our read position) or a new
// inode means logrotate has swapped the file under us.
func rotated(f *os.File, path string, lastIno uint64) bool {
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return true
	}
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	if info.Size() < pos {
		return true
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return sys.Ino != lastIno
}

func waitFor(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// resolveGlob picks the most recently modified file matching pattern,
// or "" if there are no matches. Used for log paths whose suffix moves
// between releases (postgresql-XX-main.log).
func resolveGlob(pattern string) string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return ""
	}
	sort.Slice(matches, func(i, j int) bool {
		ai, errI := os.Stat(matches[i])
		aj, errJ := os.Stat(matches[j])
		if errI != nil || errJ != nil {
			return matches[i] < matches[j]
		}
		return ai.ModTime().After(aj.ModTime())
	})
	return matches[0]
}
