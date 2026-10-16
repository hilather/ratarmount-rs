# Docker and Podman volume plugin

`ratarmount-volume-plugin` implements the [Docker volume plugin protocol v1](https://docs.docker.com/engine/extend/plugins_volume/)
over HTTP on a Unix socket. It launches a foreground `ratarmount` process per
mounted volume. It does not link the FUSE crate and is built separately from
the default CLI package. Linux, `/proc/self/mountinfo`, `/dev/fuse`, and a
matching ratarmount CLI are required.

## Install the host service

Build and install both executables, then install the socket and service units:

```sh
cargo build --release -p ratarmount -p ratarmount-volume-plugin
sudo install -m 0755 target/release/ratarmount target/release/ratarmount-volume-plugin /usr/bin/
sudo install -m 0644 packaging/docker-volume-plugin/ratarmount-volume-plugin.{socket,service} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ratarmount-volume-plugin.socket
```

Install `fusermount3` (usually the distribution's `fuse3` package). Enable
`user_allow_other` in `/etc/fuse.conf`; the plugin uses `allow_other` so container
users can access a mount owned by the service. See [sandbox.md](sandbox.md).
The socket is root-only (`0600`). Access to this API permits mounting host paths;
only give it to trusted container engines.

The service runs in the host mount namespace. Keep it there: systemd settings
such as `PrivateTmp`, `ProtectSystem`, or `PrivateMounts=yes` can create a separate
mount namespace and hide volumes from Docker. The state directory is
`/var/lib/ratarmount-volume-plugin`, and mountpoints are `mnt/<name>` below it.
The default socket is `/run/docker/plugins/ratarmount.sock`, which Docker discovers
as the `ratarmount` driver. Socket activation is supported (`LISTEN_PID`, one
`LISTEN_FDS` descriptor). For a foreground deployment:

```sh
sudo ratarmount-volume-plugin --socket /run/docker/plugins/ratarmount.sock \
  --state-dir /var/lib/ratarmount-volume-plugin \
  --ratarmount /usr/bin/ratarmount --mount-timeout 60
```

`--mount-timeout` is in seconds and must be positive. Increase it for a cold index
or a slow remote source. `journalctl -u ratarmount-volume-plugin.service` records
child exits. Child stdout/stderr are suppressed so remote credentials cannot leak
into plugin logs; to diagnose a mount failure, reproduce it with the CLI and the
same environment and options.

## Docker

```sh
docker volume create -d ratarmount -o source=/srv/datasets/shard.tar.zst corpus
docker run --rm -v corpus:/data:ro busybox ls /data

# Remote inputs are resolved by the installed ratarmount CLI.
docker volume create -d ratarmount \
  -o source=hf://datasets/org/dataset@main/shard.tar -o recursive=true hub-data
docker run --rm -v hub-data:/data:ro busybox ls /data
```

A writable sandbox with protected tests and a logical RAM cap:

```sh
docker volume create -d ratarmount \
  -o source=/srv/repos/project.git@main \
  -o overlay=tmpfs:2G -o 'readonly_globs=tests/**' \
  -o git_synthetic_head=true -o uid=1000 -o gid=1000 -o umask=022 attempt
docker run --rm --user 1000:1000 -v attempt:/work your-agent-image
```

`overlay=tmpfs` also works without an explicit size. The optional `:SIZE` is
recommended. The RAM overlay disappears at the final Unmount, on service stop,
or after a child exits normally. A crash or SIGKILL can leave temporary RAM
overlay directories behind; stale FUSE mounts are detached on restart, but the
plugin does not discover or delete abandoned CLI temporary directories. To keep
writes across stop/start, use `-o overlay=/srv/overlays/attempt`.
`readonly_globs` protects paths through the shared overlay policy; it does not
prevent reading them. The plugin never commits changes back to the source.

| Create option | Meaning |
|---|---|
| `source` | Required ratarmount input: local archive/folder, URL, `repo.git@REV`, etc. Use absolute local paths. Remote schemes depend on the installed CLI's features. |
| `overlay` | `tmpfs`, `tmpfs:SIZE`, or an absolute host overlay directory. Absent means read-only, even with `ro=false`. |
| `ro` | Boolean (`true`/`false`, `1`/`0`, empty means true). `true` conflicts with an overlay. |
| `uid`, `gid` | Unsigned 32-bit ownership overrides, passed through `-o`. |
| `umask` | Octal permissions mask, `000`–`777`. |
| `readonly_globs` | Comma-separated root-relative patterns, mapped to `--overlay-readonly`. `*`, `?`, and whole-component `**`; requires an overlay. |
| `quota` | Logical overlay byte cap, mapped to `--overlay-quota`; requires an overlay. |
| `git_synthetic_head` | Boolean; maps to `--git-synthetic-head`. Use a Git source. |
| `recursive` | Boolean; maps to `--recursive`. |
| `passthrough` | `auto`, `on`, or `off`, passed to the CLI. |

Sizes accept integer bytes or binary `K`, `M`, `G`, `T` suffixes. Names must start
with an ASCII letter/digit and use only letters, digits, `_`, `.`, `-` (up to 128
bytes). Unknown options, invalid booleans, and malformed glob paths are rejected.
An existing name can be created again with identical options or no options;
changing its definition requires Remove and Create. Remove never deletes a source
or a host overlay directory.

## Podman

Podman uses the same endpoints. Configure its plugin map in
`/etc/containers/containers.conf` (see the [containers.conf reference](https://github.com/containers/common/blob/main/docs/containers.conf.5.md)):

```toml
[engine.volume_plugins]
ratarmount = "/run/docker/plugins/ratarmount.sock"
```

```sh
sudo podman volume create --driver ratarmount \
  --opt source=/srv/datasets/shard.tar --opt overlay=tmpfs:256M corpus
sudo podman run --rm -v corpus:/data docker.io/library/busybox ls /data
```

These units target a rootful engine. Rootless engines need a user-accessible
socket, mount permissions, and mounts visible in the engine's mount namespace;
that setup is not supplied here. SELinux/AppArmor policies may also need to allow
the engine to bind the FUSE mount.

## Credentials and restart behavior

Do not put credentials in volume options, source URLs, or command arguments.
URL userinfo, query parameters (including signed URLs), and fragments are
rejected; use a clean backend URL and environment-based authentication. Unknown
options such as `HF_TOKEN`, `password`, or `token` are rejected without echoing
values. The plugin persists only validated definitions, not its environment.

Set backend credentials in the plugin's own environment, for example a root-owned
`0600` `/etc/ratarmount-volume-plugin.env`:

```ini
HF_TOKEN=your-token
```

Restart the service after changing it. Child processes inherit that environment;
HF credentials never appear in their argv or `volumes.json`. Other backend
environment variables work when supported by the CLI. All volumes share the
service identity and credentials; there is no per-container secret injection.
Do not provision secrets through Docker managed-plugin settings: Docker stores
those settings as metadata. Use the host service for credentialed sources.

Definitions are written using file fsync, atomic rename and directory fsync, with
an exclusive state lock. Mount IDs are an in-memory set: repeated Mount for one
ID adds no reference, and unknown/repeated Unmount cannot release another ID.
The final Unmount must succeed before its reference is forgotten. Remove refuses
an active volume. Each mounted child is polled and reaped; an exit clears mount
references and attempts a lazy unmount.

On restart all mounts below the plugin's mount root are lazily detached before
serving; definitions survive and mounts are recreated on the next Mount request.
A detached mount already bind-mounted into a container is not repaired. Stop
containers before restarting the plugin, and restart affected containers after a
child failure. Path/Get/List report the assigned path without mounting it; Get's
Status includes `Mounted` and `References`. All API errors use `{"Err":"..."}`.
The server caps headers at 16 KiB, bodies at 1 MiB, and concurrent connections at
32. Requests are serialized through the driver, so a slow Mount delays other
operations; idle connections have a 10-second read timeout.

## Optional managed plugin layout

[config.json](../packaging/docker-volume-plugin/config.json) supplies the Docker
managed-plugin interface, FUSE device, mount capability, host networking, and
`PropagatedMount` covering the state and mount directory. This follows Docker's
[managed-plugin configuration](https://docs.docker.com/engine/extend/config/).
It is a packaging starting point; no rootfs or registry artifact is published.
It has not been exercised against Docker in the worker sandbox.

To assemble one, place both executables, their dynamic libraries, `fusermount3`,
`umount`, CA certificates, and `/etc/fuse.conf` in a `rootfs/` alongside this config.
`/proc` must be mounted and `user_allow_other` enabled. The config provides a 1 GiB
`/dev/shm` tmpfs; adjust it to suit the overlay caps. Host paths are not visible
inside this rootfs unless explicitly bind-mounted through additional `Mounts`
entries; remote sources are the simplest starting point. Use
`docker plugin create ratarmount ./plugin-layout` and enable it locally only after
reviewing those privileges. No credentials are included in the config.

## Verification

```sh
cargo test -p ratarmount-volume-plugin
cargo test -p ratarmount-volume-plugin --no-run
./packaging/docker-volume-plugin/test-packaging.sh
# Requires a built CLI, /dev/fuse and user_allow_other:
RATARMOUNT_BIN="$PWD/target/debug/ratarmount" cargo test -p ratarmount-volume-plugin --test fuse -- --nocapture
# Requires an installed plugin and a preloaded busybox:latest (or RATARMOUNT_TEST_IMAGE):
./packaging/docker-volume-plugin/test-docker.sh
```

The Rust suite exercises HTTP framing, option-to-argv mapping, fake-mounter
lifecycle/failure paths, restart persistence, supervision, actual process reaping,
Unix sockets and systemd socket activation. The real tar mount test prints a
skip reason without `/dev/fuse`, `user_allow_other`, or a CLI binary. The Docker
script skips when required tools, the daemon, socket, device, or a local test image
are absent. It tests two concurrent containers, writable RAM overlays, protected
tests, and release on the final container exit.
