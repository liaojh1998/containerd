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

package run

import (
	gocontext "context"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cmd/ctr/commands"
	"github.com/containerd/containerd/contrib/nvidia"
	"github.com/containerd/containerd/contrib/seccomp"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

var platformRunFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "runc-binary",
		Usage: "specify runc-compatible binary",
	},
	cli.BoolFlag{
		Name:  "runc-systemd-cgroup",
		Usage: "start runc with systemd cgroup manager",
	},
	cli.StringFlag{
		Name:  "uidmap",
		Usage: "run with remapped user namespace",
	},
}

// NewContainer creates a new container
func NewContainer(ctx gocontext.Context, client *containerd.Client, context *cli.Context) (containerd.Container, error) {
	var (
		id     string
		config = context.IsSet("config")
	)
	if config {
		id = context.Args().First()
	} else {
		id = context.Args().Get(1)
	}

	var (
		opts  []oci.SpecOpts
		cOpts []containerd.NewContainerOpts
		spec  containerd.NewContainerOpts
	)

	cOpts = append(cOpts, containerd.WithContainerLabels(commands.LabelArgs(context.StringSlice("label"))))
	if config {
		opts = append(opts, oci.WithSpecFromFile(context.String("config")))
	} else {
		var (
			ref = context.Args().First()
			//for container's id is Args[1]
			args = context.Args()[2:]
		)
		opts = append(opts, oci.WithDefaultSpec(), oci.WithDefaultUnixDevices)
		if ef := context.String("env-file"); ef != "" {
			opts = append(opts, oci.WithEnvFile(ef))
		}
		opts = append(opts, oci.WithEnv(context.StringSlice("env")))
		opts = append(opts, withMounts(context))

		if context.Bool("rootfs") {
			rootfs, err := filepath.Abs(ref)
			if err != nil {
				return nil, err
			}
			opts = append(opts, oci.WithRootFSPath(rootfs))
		} else {
			snapshotter := context.String("snapshotter")
			var image containerd.Image
			i, err := client.ImageService().Get(ctx, ref)
			if err != nil {
				return nil, err
			}
			if ps := context.String("platform"); ps != "" {
				platform, err := platforms.Parse(ps)
				if err != nil {
					return nil, err
				}
				image = containerd.NewImageWithPlatform(client, i, platforms.Only(platform))
			} else {
				image = containerd.NewImage(client, i)
			}

			unpacked, err := image.IsUnpacked(ctx, snapshotter)
			if err != nil {
				return nil, err
			}
			if !unpacked {
				if err := image.Unpack(ctx, snapshotter); err != nil {
					return nil, err
				}
			}
			opts = append(opts, oci.WithImageConfig(image))
			cOpts = append(cOpts,
				containerd.WithImage(image),
				containerd.WithSnapshotter(snapshotter))
			if uidmap := context.String("uidmap"); uidmap != "" {
				container, uid, size, err := parseRemapping(uidmap, "uidmap")
				if err != nil {
					return nil, err
				}
				opts = append(opts, oci.WithUserNamespace(container, uid, size))
				if context.Bool("read-only") {
					cOpts = append(cOpts, containerd.WithRemappedSnapshotView(id, image, uid, uid))
				} else {
					cOpts = append(cOpts, containerd.WithRemappedSnapshot(id, image, uid, uid))
				}
			} else {
				// Even when "read-only" is set, we don't use KindView snapshot here. (#1495)
				// We pass writable snapshot to the OCI runtime, and the runtime remounts it as read-only,
				// after creating some mount points on demand.
				cOpts = append(cOpts, containerd.WithNewSnapshot(id, image))
			}
			cOpts = append(cOpts, containerd.WithImageStopSignal(image, "SIGTERM"))
		}
		if context.Bool("read-only") {
			opts = append(opts, oci.WithRootFSReadonly())
		}
		if len(args) > 0 {
			opts = append(opts, oci.WithProcessArgs(args...))
		}
		if cwd := context.String("cwd"); cwd != "" {
			opts = append(opts, oci.WithProcessCwd(cwd))
		}
		if context.Bool("tty") {
			opts = append(opts, oci.WithTTY)
		}
		if context.Bool("privileged") {
			opts = append(opts, oci.WithPrivileged, oci.WithAllDevicesAllowed, oci.WithHostDevices)
		}
		if context.Bool("net-host") {
			opts = append(opts, oci.WithHostNamespace(specs.NetworkNamespace), oci.WithHostHostsFile, oci.WithHostResolvconf)
		}
		if context.Bool("seccomp") {
			opts = append(opts, seccomp.WithDefaultProfile())
		}

		joinNs := context.StringSlice("with-ns")
		for _, ns := range joinNs {
			parts := strings.Split(ns, ":")
			if len(parts) != 2 {
				return nil, errors.New("joining a Linux namespace using --with-ns requires the format 'nstype:path'")
			}
			if !validNamespace(parts[0]) {
				return nil, errors.New("the Linux namespace type specified in --with-ns is not valid: " + parts[0])
			}
			opts = append(opts, oci.WithLinuxNamespace(specs.LinuxNamespace{
				Type: specs.LinuxNamespaceType(parts[0]),
				Path: parts[1],
			}))
		}
		if context.IsSet("gpus") {
			opts = append(opts, nvidia.WithGPUs(nvidia.WithDevices(context.Int("gpus")), nvidia.WithAllCapabilities))
		}
		if context.IsSet("allow-new-privs") {
			opts = append(opts, oci.WithNewPrivileges)
		}
		if context.IsSet("cgroup") {
			// NOTE: can be set to "" explicitly for disabling cgroup.
			opts = append(opts, oci.WithCgroup(context.String("cgroup")))
		}
		limit := context.Uint64("memory-limit")
		if limit != 0 {
			opts = append(opts, oci.WithMemoryLimit(limit))
		}
		for _, dev := range context.StringSlice("device") {
			opts = append(opts, oci.WithLinuxDevice(dev, "rwm"))
		}
	}

	runtimeOpts := &options.Options{}
	if runcBinary := context.String("runc-binary"); runcBinary != "" {
		if context.String("runtime") == "io.containerd.runc.v2" {
			runtimeOpts.BinaryName = runcBinary
		} else {
			return nil, errors.New("specifying runc-binary is only supported for \"io.containerd.runc.v2\" runtime")
		}
	}
	if context.Bool("runc-systemd-cgroup") {
		if context.String("runtime") == "io.containerd.runc.v2" {
			if context.String("cgroup") == "" {
				// runc maps "machine.slice:foo:deadbeef" to "/machine.slice/foo-deadbeef.scope"
				return nil, errors.New("option --runc-systemd-cgroup requires --cgroup to be set, e.g. \"machine.slice:foo:deadbeef\"")
			}
			runtimeOpts.SystemdCgroup = true
		} else {
			return nil, errors.New("specifying runc-systemd-cgroup is only supported for \"io.containerd.runc.v2\" runtime")
		}
	}
	cOpts = append(cOpts, containerd.WithRuntime(context.String("runtime"), runtimeOpts))

	opts = append(opts, oci.WithAnnotations(commands.LabelArgs(context.StringSlice("label"))))
	var s specs.Spec
	spec = containerd.WithSpec(&s, opts...)

	cOpts = append(cOpts, spec)

	// oci.WithImageConfig (WithUsername, WithUserID) depends on access to rootfs for resolving via
	// the /etc/{passwd,group} files. So cOpts needs to have precedence over opts.
	return client.NewContainer(ctx, id, cOpts...)
}

func getNewTaskOpts(context *cli.Context) []containerd.NewTaskOpts {
	var (
		tOpts []containerd.NewTaskOpts
	)
	if context.Bool("no-pivot") {
		tOpts = append(tOpts, containerd.WithNoPivotRoot)
	}
	if uidmap := context.String("uidmap"); uidmap != "" {
		parts := strings.Split(uidmap, ":")
		uid, _ := parseRemappingPart(parts[1], "uidmap", "uid")
		tOpts = append(tOpts, containerd.WithUIDMap(uid))
	}
	if gidmap := context.String("gidmap"); gidmap != "" {
		parts := strings.Split(gidmap, ":")
		gid, _ := parseRemappingPart(parts[1], "gidmap", "gid")
		tOpts = append(tOpts, containerd.WithGIDMap(gid))
	}
	return tOpts
}

func parseRemapping(remapping, idType string) (uint32, uint32, uint32, error) {
	parts := strings.Split(remapping, ":")
	if len(parts) != 3 {
		return 0, 0, 0, errors.New("remapping user namespace using --" + idType + " requires the format 'container-id:id:size'")
	}
	container, err := parseRemappingPart(parts[0], idType, "container id")
	if err != nil {
		return 0, 0, 0, err
	}
	id, err := parseRemappingPart(parts[1], idType, "id")
	if err != nil {
		return 0, 0, 0, err
	}
	size, err := parseRemappingPart(parts[2], idType, "remapping size")
	if err != nil {
		return 0, 0, 0, err
	}
	return container, id, size, nil
}

func parseRemappingPart(part, idType, partName string) (uint32, error) {
	value, err := strconv.ParseUint(part, 0, 32)
	if err != nil {
		return 0, errors.New(idType + " encountered invalid " + partName + ": " + part)
	}
	return uint32(value), nil
}

func validNamespace(ns string) bool {
	linuxNs := specs.LinuxNamespaceType(ns)
	switch linuxNs {
	case specs.PIDNamespace,
		specs.NetworkNamespace,
		specs.UTSNamespace,
		specs.MountNamespace,
		specs.UserNamespace,
		specs.IPCNamespace,
		specs.CgroupNamespace:
		return true
	default:
		return false
	}
}
