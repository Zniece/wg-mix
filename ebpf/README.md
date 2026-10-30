# wgmix-ebpf

用 TC egress + XDP ingress 原地改写 WireGuard 报文的 4 字节 `Type`。
内核 WireGuard 继续负责加解密和 MAC；eBPF 只改线上 Type，并增量更新 UDP 校验和。

## Profile

```
canonical type : 1=init  2=response  3=cookie  4=transport
wire type      : X       Y           Z         W
MAC1/MAC2 输入 : 用 canonical type 参与哈希
线上报文       : Type = wire type，其余字节和长度不变
```

MAC 始终按 canonical type 计算。非 Linux 端点必须使用打过 canonical MAC 补丁的
`wgmix`，否则两端 MAC 输入不一致。

## 构建

在仓库根目录：

```bash
make            # 同时生成 wgmix 和 wgmix-ebpf
```

只构建 eBPF 部分：

```bash
cd ebpf
make bpf        # 生成 bpf/typeobfs_bpfel.o 和 bpf/typeobfs_bpfeb.o
make            # 生成静态 wgmix-ebpf
```

要求：clang（支持 `-target bpf`）、Go 1.25+。产物不依赖 libbpf、cgo、BTF 或 vmlinux.h。

## 使用

```bash
# 两端使用同一组 wire type
sudo ./wgmix-ebpf attach -iface eth0 \
  -listen 51820 -peer 51820 \
  -wire 4133012198,109490640,123397600,333443179 \
  -xdp native

sudo ./wgmix-ebpf status -iface eth0
sudo ./wgmix-ebpf detach -iface eth0
```

- `-listen`：本地 WireGuard 端口，逗号分隔。
- `-peer`：对端端口，逗号分隔；纯监听端可以只写 `-listen`。
- `-xdp`：`native`（默认）/ `skb` / `off`；`off` 只挂 TC egress，用于抓包调试。

### wg-quick

安装二进制，并使用仓库根目录改过的 `wg-quick`：

```bash
install -m755 wgmix-ebpf /usr/local/bin/
cp /usr/bin/wg-quick /usr/bin/wg-quick.bak
install -m755 ../wg-quick /usr/bin/wg-quick
```

配置只需一行：

```ini
[Interface]
Address = 10.0.0.1/24
PrivateKey = ...
ListenPort = 51820
WgBin = wgmix-ebpf
```

`wg-quick up` 会创建内核 WireGuard 接口、自动挂载 bpffs、推导端口和出口网卡，
然后 attach；`down` 时自动 detach。XDP 固定 native，wire profile 固定为上面的
四个常量。纯监听端不写 peer `Endpoint`，出口网卡取默认路由。

## 约束

- 只改 Type：包长、时序和方向特征仍是标准 WireGuard，深度 DPI 仍可能识别。
- 端口必须专用；与其它 UDP 服务共用会误改无关流量。
- 生产环境使用 native XDP；generic XDP 在 GRO 之后，可能只改到合并包的第一个报文。
- 隧道 MTU 应比 underlay MTU 小 80 字节；例如 WSL NAT 的 1280 用 1200。
- 解析支持 eth / VLAN / IPv4 / IPv6 扩展头 / UDP；PPPoE 未覆盖。
- 不访问内核结构体，不依赖 CO-RE/BTF。

## 测试

```bash
# 内核 WG + eBPF 与 patched wgmix 互通
sudo test/wgquick-interop.sh

# 纯监听端（peer 无 Endpoint）
sudo test/wgquick-listener.sh
```

两个脚本都需要 root、veth/netns，以及仓库根目录的 `wgmix` 和 `wg-quick`。
WSL 的 veth 只支持 generic XDP，脚本通过 `WG_MIX_XDP=skb` 测试。

## License

MIT
