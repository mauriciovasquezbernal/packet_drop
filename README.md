# packet drop

The packet drop Gadget drops networking packets coming or going to given set of IP ranges.


## Usage

0. Install the `ig` binary on Linux: https://inspektor-gadget.io/docs/latest/reference/install-linux
1. Build the gadget

```bash
$ sudo ig image build . -t packet_drop
```

3. (optional) Push the image to a container registry

```bash
$ sudo ig image tag packet_drop <registry>/<image>:<tag>
$ sudo ig image push <registry>/<image>:<tag>
```

4. Run the gadget

```bash
$ sudo ig run packet_drop --cidrs=192.168.1.0/16,8.8.8.8/32
```

By default the gadget attaches to all running containers. To attach to a networking interface on the host use the `--iface` flag:

```bash
$ sudo ig run packet_drop --cidrs=192.168.1.0/16,8.8.8.8/32 --iface=eth0
```

## TODO
- Support IPv6
