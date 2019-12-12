## Summary
This is a demo of comparison between FUSE-OverlayFS and Lchown for remapping user namespaces.

## Requirements
* Install https://github.com/containers/fuse-overlayfs
* Install `containerd` and `ctr` as indicated in https://github.com/containerd/containerd/blob/master/BUILDING.md through this commit.

## Lchown Steps
1. Run `sudo containerd`.
2. In another terminal, run `sudo ctr image pull docker.io/library/alpine:latest`.
3. In the other terminal, run `sudo ctr run --tty --rm --uidmap 0:1234:10000 --gidmap 0:2345:10000 docker.io/library/alpine:latest alpine-remapped` to see `alpine` get remapped into user namespace.

## FUSE-OverlayFS Steps
1. Run `sudo go run ./main.go /var/run/fuseoverlay.sock /tmp/snapshots` from here. This will open a server to start a FUSE-OverlayFS snapshotter.
2. In another terminal, run as root: `sudo su`.
3. Through the root terminal, run `containerd config default > /etc/containerd/config.toml` to create a default set of configs.
4. Add the following to the bottom of the `/etc/containerd/config.toml`:
```
[proxy_plugins]
  [proxy_plugins."fuse-overlayfs"]
    type = "snapshot"
    address = "/var/run/fuseoverlay.sock"
```
5. In a separate terminal from the first two, run `sudo containerd`.
6. In the root terminal, run `CONTAINERD_SNAPSHOTTER=fuse-overlayfs ctr image pull docker.io/library/alpine:latest` to get a snapshot of `alpine`.
7. In the root terminal, run `CONTAINERD_SNAPSHOTTER=fuse-overlayfs ctr run --tty --rm --uidmap 0:1234:10000 --gidmap 0:2345:10000 --remapper fuse-overlayfs docker.io/library/alpine:latest alpine-remapped` to see `alpine` get remapped into user namespace very quickly.

## Note
* It might be required after very run to remove the `docker.io/library/alpine:latest` image so that they can be pulled through the other file system. To do so, run `sudo ctr image remove docker.io/library/alpine:latest`.
* Too see a more pronounced effect of chown's huge overhead, use `docker.io/library/bash:latest` in place of `docker.io/library/alpine:latest`.
