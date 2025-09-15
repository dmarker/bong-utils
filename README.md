[10]: https://github.com/dmarker/bong-kmods
[11]: https://github.com/dmarker/ring

[20]: https://reviews.freebsd.org/D50241

[30]: https://www.freshports.org/net/dhcpcd
[31]: https://man.freebsd.org/cgi/man.cgi?query=envsubst
[32]: https://www.freshports.org/devel/gettext-runtime
[33]: https://man.freebsd.org/cgi/man.cgi?query=ng_tee

# bong-utils
Userland utilities meant to be used with [bong-kmods][10].

These require that you have built and installed [bong-kmods][10] as they need headers
from [bong-kmods][10].

[jeiface](jeiface/jeiface) does assume this review is merged:
* changes to [ngctl(8)][20] to add `-j` option.

WARNING: This is all a work in progress. I'm still testing!

## jeiface
This utility is meant to be used from jail.conf(5) to create an ng_eiface(4) in
a jail (and optionally set its MAC address). Both the netgraph(4) node name and
the ifconfig(8) interface name are kept in sync and renamed to whatever you
chose.

This will create an ng_eiface(4) in jail `demojail`.
```# jeiface demojail jail0```

## ngportal
This utility is to simplify the use of ng_wormhole(4). Without it, opening a
wormhole is more involved and requires scraping an ID from ngctl(8) output.

With this utility you can connect two existing netgraph(4) nodes that are each
in a separate vnet(9) to each other with a single command and optionally name
both ends of the wormhole.

## ngpcap
This utility is to simplify using ng_pcap(4) with tcpdump(1). You still have
to pipe your output to tcpdump(1) but it puts the correct header and then
streams pcap(3) records to make this trivial.

This is primarily a debugging tool for netgraph layer 2 and layer 3 nodes.
Because the whole point is to get multiple packet sources at once you get to
specify up to NG_PCAP_MAX_LINKS on the command line.

Each link is specified with `<type:node:hook:>` which tells ng_pcap(4) what kind
of packets it recieves from a `node:hook` netgraph(4) path. `type` must be one
of:
* ether
* inet
* inet6

While no checking will be done by ng_pcap(4) nodes, it will add fake ethernet
headers for IPv4 and IPv6 connections so that all your layer 2 and layer 3
packets can be given to tcpdump together.

Here is an example connecting two different ng_tee(4) which is probably what
you will always be connecting to when debugging:
```
ngpcap inet6:tee0:right2left ether:tee1:left2right | tcpdump -r -
```

## netgraph rc(8) script
Don't get excited, this isn't the perfect netgraph rc(8) script you are hoping
for. In fact its a cop-out.

I've come to believe that even attempting such a thing is a fools errand. But
who knows, I am not the worlds best sh(1) practitioner.

This is just going to pass a file to ngctl(8) and after that make sure netif
interfaces (so ng_ether(4), ng_eiface(4), ng_iface(4) for example), get renamed
to match the netgraph(4) node name. So not much taken care of for you. But by
renaming netif interfaces to something you expect you can now finish all config
using the usual `ifconfig_<ifname>=...` stanzas of rc.conf(8) or any other way
you prefer to configure your network (I like [net/dhcpcd][30]).

### examples
These are actual examples I use on my firewall and my workstation. Just to give
you an idea of what you can put into files. They do assume you have
[envsubst(1)][31] (from [devel/gettext-runtime][32]) and exlain in comments how
to generate the actual file.

[split4ula](examples/split4ula) is what I run on my firewall as my ISP only
provides a /64 prefix for IPv6. This allows me to share internet with WiFi and
local area network (using GUA addresses) and at the same time have separate
ULA (and IPv4) networks for them. This means I can use DHCPv6 on my LAN which
allows me to use SIIT as well. This requires the ng_ula4tag(4) from
[bong-kmods][10].

[split4ula.pcap](examples/split4ula.pcap) is the same as the previous but with
[ng_tee(4)][33] strategically located for ngpcap(8).

[workstation2](examples/workstation2) is what I run on my workstation. This is just
as trivial as it looks. It makes two ng_bridge(4)s with one of them connected to
the `lower` hook of an ng_ether(4) that I later put into promiscuous mode in
rc.conf(8). I do *not* attach the `upper` hook of the ng_ether(4) but instead
creates two ng_eiface(4) with one attached to each bridge. There is one advantage
to this way over the traditional: by having two interfaces I can let [net/dhcpcd][30]
configure the ng_eiface(4) and it won't change the promiscuous settings I put on
the physical device. This is because I rename it `brX<ifacename>` and filter out
all interfaces starting with `br` in `dhcpcd.conf`.
