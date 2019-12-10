// +build !windows

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package containerd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/mount"
	"github.com/opencontainers/image-spec/identity"
)

// WithRemappedSnapshot creates a new snapshot and remaps the uid/gid for the
// filesystem to be used by a container with user namespaces
func WithRemappedSnapshot(id string, i Image, uid, gid uint32) NewContainerOpts {
	return withRemappedSnapshotBase(id, i, uid, gid, false)
}

// WithRemappedSnapshotView is similar to WithRemappedSnapshot but rootfs is mounted as read-only.
func WithRemappedSnapshotView(id string, i Image, uid, gid uint32) NewContainerOpts {
	return withRemappedSnapshotBase(id, i, uid, gid, true)
}

func withRemappedSnapshotBase(id string, i Image, uid, gid uint32, readonly bool) NewContainerOpts {
	return func(ctx context.Context, client *Client, c *containers.Container) error {
		diffIDs, err := i.(*image).i.RootFS(ctx, client.ContentStore(), client.platform)
		if err != nil {
			return err
		}

		var (
			parent   = identity.ChainID(diffIDs).String()
			usernsID = fmt.Sprintf("%s-%d-%d", parent, uid, gid)
		)
		c.Snapshotter, err = client.resolveSnapshotterName(ctx, c.Snapshotter)
		if err != nil {
			return err
		}
		snapshotter, err := client.getSnapshotter(ctx, c.Snapshotter)
		if err != nil {
			return err
		}
		if _, err := snapshotter.Stat(ctx, usernsID); err == nil {
			if _, err := snapshotter.Prepare(ctx, id, usernsID); err == nil {
				c.SnapshotKey = id
				c.Image = i.Name()
				return nil
			} else if !errdefs.IsNotFound(err) {
				return err
			}
		}
		mounts, err := snapshotter.Prepare(ctx, usernsID+"-remap", parent)
		if err != nil {
			return err
		}

		if readonly {
			// if err := remapRootFSShiftFUSEReadOnly(ctx, mounts, uid, gid); err != nil {
			if err := remapRootFSShiftFUSEReadOnly(ctx, mounts, uid, gid); err != nil {
				snapshotter.Remove(ctx, usernsID)
				return err
			}
		} else {
			if err := remapRootFS(ctx, mounts, uid, gid); err != nil {
				snapshotter.Remove(ctx, usernsID)
				return err
			}
		}

		if err := snapshotter.Commit(ctx, usernsID, usernsID+"-remap"); err != nil {
			return err
		}
		if readonly {
			_, err = snapshotter.View(ctx, id, usernsID)
		} else {
			_, err = snapshotter.Prepare(ctx, id, usernsID)
		}
		if err != nil {
			return err
		}
		c.SnapshotKey = id
		c.Image = i.Name()
		return nil
	}
}

func remapRootFS(ctx context.Context, mounts []mount.Mount, uid, gid uint32) error {
	for _, mount := range mounts {
		fmt.Printf("options: %s\nsource: %s\n", mount.Options, mount.Source)
	}
	return mount.WithTempMount(ctx, mounts, func(root string) error {
		return filepath.Walk(root, incrementFS(root, uid, gid))
	})
}

func getLowerDir(ops []string) string {
	for _, op := range ops {
		strings.HasPrefix(op, "lower=")
		var opStart = strings.Index(op, "=")
		return op[opStart+1 : len(op)]
	}
	return ""
}

func getLowerDirs(mounts []mount.Mount) string {
	var lowerdirs []string
	for _, mount := range mounts {
		if mount.Type == "overlay" {
			lowerdirs = append(lowerdirs, getLowerDir(mount.Options))
		}
	}
	return strings.Join(lowerdirs, ":")
}

func remapRootFSShiftFUSEReadOnly(ctx context.Context, mounts []mount.Mount, uid, gid uint32) error {
	var lowerMounts = getLowerDirs(mounts)
	lowerMountOpt := "lowerdir=" + lowerMounts
	uidMapopt := fmt.Sprintf("uidmapping=0:%d:1000", uid)
	fmt.Println(lowerMountOpt, uidMapopt)

	return mount.WithTempMount(ctx, mounts, func(root string) error {
		fuseOverlayCmd := exec.Command("fuse-overlayfs", "-o", lowerMountOpt,
			"-o", uidMapopt, root)
		out, err := fuseOverlayCmd.Output()
		if err != nil {
			fmt.Printf("Error while remapping via fuseoverlayfs. output: %s\n", string(out))
		}

		info, err := os.Lstat(root)
		if err != nil {
			fmt.Printf("error while statting is %s\n", err.Error())
		}
		stat := info.Sys().(*syscall.Stat_t)
		fmt.Printf("uid/gid for %s is %d/%d\n", root, stat.Uid, stat.Gid)

		return err
	})

}

func incrementFS(root string, uidInc, gidInc uint32) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		var (
			stat = info.Sys().(*syscall.Stat_t)
			u, g = int(stat.Uid + uidInc), int(stat.Gid + gidInc)
		)
		chownret := os.Lchown(path, u, g)
		info, err = os.Lstat(path)
		stat = info.Sys().(*syscall.Stat_t)
		fmt.Printf("chowned %s result uid: %d, gid: %d\n", path, stat.Uid, stat.Gid)
		// be sure the lchown the path as to not de-reference the symlink to a host file
		//return os.Lchown(path, u, g)
		return chownret
	}
}
