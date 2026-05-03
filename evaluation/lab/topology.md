# Laboratory topology

Air-gapped IPv4 /24 segment for the dissertation evaluation. No
route from this segment to the public Internet or to any production
network. All hosts run on the same controller host as KVM guests on
a single Linux bridge attached to the evaluation segment.

```
                 +------------------------------+
                 |  Controller host (CH)        |
                 |  - shadowtrap-controller     |
                 |  - PostgreSQL 16             |
                 |  - libvirtd 9.x              |
                 |  - nftables shadowtrap table |
                 |  IP: 10.10.42.2/24           |
                 +---------------+--------------+
                                 |
              ----------- Linux bridge stb******* ---------
              |             |             |             |
       +------+----+ +------+----+ +------+----+ +------+----+
       | Prod J/H  | | Prod FS   | | Prod Mon  | | Attacker  |
       | 10.10.42  | | 10.10.42  | | 10.10.42  | | 10.10.42  |
       |   .10     | |   .11     | |   .12     | |   .200    |
       +-----------+ +-----------+ +-----------+ +-----------+

       + 14 honeypots provisioned on free addresses in
         10.10.42.13 .. 10.10.42.199 by ShadowTrap
```

## Hosts

| Hostname / role | IP | OS / image | Notes |
| --- | --- | --- | --- |
| Controller | 10.10.42.2 | Debian 12 / 8 vCPU / 16 GiB | Runs `shadowtrap-controller`, PostgreSQL, libvirtd. |
| Prod J/H (jumphost) | 10.10.42.10 | Ubuntu 22.04 LTS | Lateral-movement target with sshd. Static admin creds *not* shared with pots. |
| Prod FS (file server) | 10.10.42.11 | Windows Server 2022 | Lateral-movement target with SMB. |
| Prod Mon (monitoring) | 10.10.42.12 | Ubuntu 22.04 LTS | Issues background probes for T5. |
| Attacker | 10.10.42.200 | Kali 2024.x | Runs scenario scripts. |
| Pots | 10.10.42.13–.199 (allocated) | Ubuntu 24.04 cloud image | Per-pot identity from controller. |

## Ground truth for sweep test

`lab/ground-truth.txt` lists addresses **occupied** at sweep time,
one per line. Used by T2.2 to score the sweep allocator.

```
10.10.42.1     # gateway
10.10.42.2     # controller
10.10.42.10    # prod jumphost
10.10.42.11    # prod file server
10.10.42.12    # prod monitoring
10.10.42.200   # attacker
```

Six addresses are occupied; the sweep should report 247 free out of
253 host addresses (254 minus 6 occupied minus the network address).

## Ethical / containment posture

The segment has no NAT, no upstream router, and no DNS resolver
reachable from inside it. The attacker VM is on the same isolated
bridge. Outbound traffic from any pot is dropped at both the
per-NIC libvirt nwfilter and the host-bridge nftables backstop. No
real attacker traffic is solicited; all attacker behaviour is
scripted from the attacker VM.

## Reproducing the topology

```sh
$ cd shadowtrap/evaluation
$ ./lab/build-pot-image.sh           # builds the qcow2 base image
$ ./lab/setup.sh                     # records lab inventory
```

`setup.sh` is idempotent and only collects inventory; bringing the
"production" hosts up is operator-driven, since they vary per
environment. A `lab/example-virsh-domains/` directory has minimal
domain XML stubs you can adapt.
