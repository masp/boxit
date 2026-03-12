//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// SetupMountNamespace configures the mount namespace with an overlayfs root.
// All existing mounts become read-only with copy-on-write (writes go to a tmpfs
// upper layer and are discarded on exit). The given cwd is bind-mounted
// read-write so changes there are transparent and persistent.
//
// Must be called from inside a user+mount namespace (CLONE_NEWUSER | CLONE_NEWNS).
func SetupMountNamespace(cwd string) error {
	cwd, err := filepath.Abs(cwd)
	if err != nil {
		return fmt.Errorf("resolve cwd: %w", err)
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return fmt.Errorf("eval cwd symlinks: %w", err)
	}

	// 1. Prevent mount event propagation to the host
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}

	// 2. Create a tmpfs workspace for overlay upper/work dirs
	ovlBase := "/tmp/.boxit-ovl"
	if err := os.MkdirAll(ovlBase, 0700); err != nil {
		return fmt.Errorf("create overlay base: %w", err)
	}
	if err := syscall.Mount("tmpfs", ovlBase, "tmpfs", 0, "size=4G"); err != nil {
		return fmt.Errorf("mount overlay tmpfs: %w", err)
	}

	upper := filepath.Join(ovlBase, "upper")
	work := filepath.Join(ovlBase, "work")
	newroot := filepath.Join(ovlBase, "newroot")
	for _, d := range []string{upper, work, newroot} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", d, err)
		}
	}

	// 3. Mount overlayfs: lowerdir=/ gives COW over the root filesystem.
	// Writes land in the tmpfs upper layer and are discarded on exit.
	if err := mountOverlay("/", upper, work, newroot); err != nil {
		return err
	}

	// 4. Re-mount submounts into the overlay. The overlay only covers the root
	// filesystem; separate mounts (/home on another partition, etc.) appear
	// empty without this step.
	mounts, err := parseMountInfo()
	if err != nil {
		return fmt.Errorf("parse mountinfo: %w", err)
	}

	sort.Slice(mounts, func(i, j int) bool {
		return len(mounts[i]) < len(mounts[j])
	})

	// These are handled separately below
	specialPrefixes := []string{"/proc", "/sys", "/dev", "/tmp", "/run", ovlBase}

	for _, mp := range mounts {
		if mp == "/" {
			continue
		}

		skip := false
		for _, sp := range specialPrefixes {
			if mp == sp || strings.HasPrefix(mp, sp+"/") {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Skip if this mount is at or under cwd (cwd gets its own bind mount)
		if mp == cwd || strings.HasPrefix(mp, cwd+"/") {
			continue
		}

		dest := filepath.Join(newroot, mp)
		if err := os.MkdirAll(dest, 0755); err != nil {
			continue
		}
		if err := syscall.Mount(mp, dest, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
			continue
		}
		// Remount read-only
		syscall.Mount("", dest, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, "")
	}

	// 5. Mount special filesystems
	specials := []struct {
		src, dest, fstype string
		flags             uintptr
		data              string
	}{
		{"/proc", filepath.Join(newroot, "proc"), "", syscall.MS_BIND | syscall.MS_REC, ""},
		{"/dev", filepath.Join(newroot, "dev"), "", syscall.MS_BIND | syscall.MS_REC, ""},
		{"/sys", filepath.Join(newroot, "sys"), "", syscall.MS_BIND | syscall.MS_REC, ""},
		{"tmpfs", filepath.Join(newroot, "run"), "tmpfs", 0, ""},
		{"tmpfs", filepath.Join(newroot, "tmp"), "tmpfs", 0, "size=4G"},
	}
	for _, s := range specials {
		os.MkdirAll(s.dest, 0755)
		syscall.Mount(s.src, s.dest, s.fstype, s.flags, s.data)
	}

	// 6. Bind mount the real CWD read-write (transparent, persistent writes).
	// This must come after the submount loop so it takes precedence.
	cwdDest := filepath.Join(newroot, cwd)
	if err := os.MkdirAll(cwdDest, 0755); err != nil {
		return fmt.Errorf("mkdir cwd dest: %w", err)
	}
	if err := syscall.Mount(cwd, cwdDest, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind mount CWD %s: %w", cwd, err)
	}

	// 7. Pivot into the overlay root
	oldRoot := filepath.Join(newroot, ".old_root")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return fmt.Errorf("mkdir old_root: %w", err)
	}
	if err := syscall.PivotRoot(newroot, oldRoot); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir /: %w", err)
	}

	// 8. Detach old root (backing mounts stay alive via kernel references)
	if err := syscall.Unmount("/.old_root", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount old root: %w", err)
	}
	os.Remove("/.old_root")

	// 9. Land in the working directory
	return os.Chdir(cwd)
}

// mountOverlay tries kernel overlayfs first (requires kernel 5.11+ in user
// namespaces), then falls back to fuse-overlayfs (works on older kernels).
func mountOverlay(lower, upper, work, merged string) error {
	ovlOpts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)

	// Try kernel overlayfs
	if err := syscall.Mount("overlay", merged, "overlay", 0, ovlOpts); err == nil {
		return nil
	}

	// Fall back to fuse-overlayfs (standard rootless container solution)
	if fuseOvl, err := exec.LookPath("fuse-overlayfs"); err == nil {
		out, err := exec.Command(fuseOvl, "-o", ovlOpts, merged).CombinedOutput()
		if err == nil {
			return nil
		}
		return fmt.Errorf("fuse-overlayfs failed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return fmt.Errorf("overlay mount failed: install fuse-overlayfs or use kernel 5.11+")
}

// parseMountInfo reads /proc/self/mountinfo and returns unique mount point paths.
func parseMountInfo() ([]string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}

	var mounts []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mp := unescapeMountPath(fields[4])
		if !seen[mp] {
			seen[mp] = true
			mounts = append(mounts, mp)
		}
	}
	return mounts, nil
}

// unescapeMountPath decodes octal escape sequences used in mountinfo
// (e.g. \040 for space, \012 for newline).
func unescapeMountPath(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			oct := 0
			valid := true
			for j := 1; j <= 3; j++ {
				c := s[i+j]
				if c < '0' || c > '7' {
					valid = false
					break
				}
				oct = oct*8 + int(c-'0')
			}
			if valid {
				b.WriteByte(byte(oct))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
