package fs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Getcd returns absolute path of the caller.
func Getcd(skip int) string {
	var dir string
	if dir = Geted(); strings.HasPrefix(dir, os.TempDir()) {
		pc, _, _, _ := runtime.Caller(skip + 1)
		function := runtime.FuncForPC(pc)
		filename, _ := function.FileLine(0)
		return path.Dir(filename)
	}
	return dir
}

// Geted returns an absolute path to the executable.
func Geted() string {
	if dir, err := filepath.Abs(filepath.Dir(os.Args[0])); err == nil {
		return dir
	}
	panic("Failed to retrieve executable directory")
}

// Getwd returns a absolute path of the current directory.
func Getwd() string {
	if cwd, err := os.Getwd(); err == nil {
		cwd, _ = filepath.Abs(cwd)
		return cwd
	}
	panic("Failed to retrieve current working directory")
}

// Abs finds the absolute path for the given path.
// Supported Formats:
//   - empty path  => current working directory.
//   - '.', '..' & '~'
//
// *NOTE* Abs does NOT check the existence of the path.
func Abs(path string) string {
	var abs string
	cwd, _ := os.Getwd()

	if path == "" || path == "." {
		abs = cwd

	} else if path == ".." {
		abs = filepath.Join(cwd, path)

	} else if strings.HasPrefix(path, "~/") {
		abs = filepath.Join(UserDir(), path[2:])

	} else if strings.HasPrefix(path, "./") {
		abs = filepath.Join(cwd, path[2:])

	} else if strings.HasPrefix(path, "../") {
		abs = filepath.Join(cwd, "..", path[2:])

	} else {
		return path
	}
	return abs
}

// Copy recursively copies files/(sub)directoires into the given path.
// *NOTE* It uses platform's native copy commands (windows: copy, *nix: rsync).
func Copy(src, dst string) (err error) {
	var cmd *exec.Cmd
	src, dst = Abs(src), Abs(dst)
	// Determine the command we need to use.
	if runtime.GOOS == "windows" {
		// *NOTE* Not sure this will work correctly, we don't have Windows to test.
		if IsFile(src) {
			cmd = exec.Command("copy", src, dst)
		} else {
			cmd = exec.Command("xcopy", src, dst, "/S /E")
		}
	} else {
		cmd = exec.Command("rsync", "-a", src, dst)
	}

	if stdout, err := cmd.StdoutPipe(); err == nil {
		if stderr, err := cmd.StderrPipe(); err == nil {
			// Start capturing the stdout/err.
			_ = cmd.Start()
			_, _ = io.Copy(os.Stdout, stdout)
			buffer := new(bytes.Buffer)
			_, _ = buffer.ReadFrom(stderr)
			_ = cmd.Wait()
			if cmd.ProcessState.String() != "exit status 0" {
				err = fmt.Errorf("\t%s\n", buffer.String()) //nolint
			}
		}
	}
	return
}

// Exists check if the given path exists.
func Exists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Find matches files with regular expression pattern under the given root.
func Find(root string, pattern *regexp.Regexp) (paths []string) {
	if Exists(root) {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, e error) error {
			if pattern.MatchString(path) {
				paths = append(paths, info.Name())
			}
			return e
		})
	}
	return
}

// Grep searches text files via regular expression under the given path,
// paths of the files contain matched line(s) will be returned.
//func Grep(root string, pattern *regexp.Regexp) (paths []string) {
//	panic(fmt.Errorf("Not Implemented"))
//}

// Glob recursively finds the names of all files matching pattern under the given path.
func Glob(path string, pattern string) (matches []string, err error) {
	err = filepath.Walk(path, func(path string, info os.FileInfo, e error) error {
		if e == nil {
			if info.IsDir() {
				if filenames, e := filepath.Glob(filepath.Join(path, pattern)); e == nil {
					matches = append(matches, filenames...)
				}
			}
		}
		return e
	})
	return
}

// IsDir checks if the given path is a directory.
func IsDir(path string) bool {
	src, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return src.IsDir()
}

// IsFile checks if the given path is a file.
func IsFile(path string) bool {
	src, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !src.IsDir()
}

// UserDir finds base path of current system user.
func UserDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}
