Kubernetes The Hard Way - Proxmox LXC-based Cluster
===================================================

[This document](https://github.com/cloud-helpers/kubernetes-hard-way-proxmox-lxc/blob/master/README.md)
aims at providing a full hands-on guide to set up a Kubernets
cluster on [Proxmox-based](https://www.proxmox.com/en/proxmox-ve/features)
[LXC containers](https://linuxcontainers.org/#LXC).
Using [LXD](https://linuxcontainers.org/#LXD) rather than Proxmox should
not make much difference.
Contributions are welcome to complemenent that guide.

All the nodes are setup with CentOS distributions, and insulated thanks to
a gateway. Hence, all the traffic from outside the cluster is channelled
through the gateway.

# References
* [Kubernetes The Hard Way - Bare Metal](https://github.com/Praqma/LearnKubernetes/blob/master/kamran/Kubernetes-The-Hard-Way-on-BareMetal.md),
  by [Tobias Schöneberg](https://github.com/metas-ts),
  February 2018, GitHub
* [Kubernetes The Hard Way](https://github.com/kelseyhightower/kubernetes-the-hard-way),
  by [Kelsey Hightower](https://github.com/kelseyhightower),
  2017-2018, GitHub
* [Run kubernetes inside LXC container](https://medium.com/@kvaps/run-kubernetes-in-lxc-container-f04aa94b6c9c),
  by [Andrei Kvapil (aka kvaps)](https://medium.com/@kvaps),
  August 2018, Medium
* [Kubernetes reference documentation](https://kubernetes.io/docs/reference/)
* [Getting started guide on installing a multi-node Kubernetes cluster
  on Fedora with flannel](https://kubernetes.io/docs/getting-started-guides/fedora/flannel_multi_node_cluster/)

# Host preparation
In that section, it is assumed that we are logged on the Proxmox host as `root`.

Though it is not strictly necessary, the cluster may be accessible from
outside (from the Internet).

The following parameters are used in the remaining of the guide, and may be
adapted according to your configuration:
+ IP of the routing gateway on the host (typically ends with `.254`: `HST_GTW_IP`
+ (Potentially virtual) MAC address of the Kubernetes cluster gateway: `GTW_MAC`
+ IP address of the Kubernetes cluster gateway: `GTW_IP`
+ VM ID of the Kubernetes cluster gateway: `103`
+ The private IP addresses and host names of all the nodes correspond
  to
  [Tobias' guide](https://github.com/Praqma/LearnKubernetes/blob/master/kamran/Kubernetes-The-Hard-Way-on-BareMetal.md#provision-vms-in-kvm),
  and a summary is provided below

| VM ID | Private IP  |    Host name (full)     | Short name  |
| ----- | ----------- | ----------------------- | ----------- |
|  103  | 10.240.0.2  | gwkublxc.example.com    | gwkublxc    |
|  211  | 10.240.0.11 | etcd1.example.com       | etcd1       |
|  212  | 10.240.0.12 | etcd2.example.com       | etcd2       |
|  220  | 10.240.0.20 | controller.example.com  | controller  |
|  221  | 10.240.0.21 | controller1.example.com | controller1 |
|  222  | 10.240.0.22 | controller2.example.com | controller2 |
|  231  | 10.240.0.31 | worker1.example.com     | worker1     |
|  232  | 10.240.0.32 | worker2.example.com     | worker2     |
|  240  | 10.240.0.40 | lb.example.com          | lb          |
|  241  | 10.240.0.41 | lb1.example.com         | lb1         |
|  242  | 10.240.0.42 | lb2.example.com         | lb2         |

* Extract of the host network configuration:
```bash
$ cat /etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

auto eno1
iface eno1 inet manual

auto eno2
iface eno2 inet manual

auto bond0
iface bond0 inet manual
        bond-slaves eno1 eno2
        bond-miimon 100
        bond-mode active-backup

# vmbr0: Bridging. Make sure to use only MAC adresses that were assigned to you.
auto vmbr0
iface vmbr0 inet static
        address ${HST_IP}
        netmask 255.255.255.0
        gateway ${HST_GTW_IP}
        bridge_ports bond0
        bridge_stp off
        bridge_fd 0

auto vmbr3
iface vmbr3 inet static
        address 10.240.0.2
        netmask 255.255.255.0
        bridge-ports none
        bridge-stp off
        bridge-fd 0
        post-up echo 1 > /proc/sys/net/ipv4/ip_forward
        post-up iptables -t nat -A POSTROUTING -s '10.240.0.0/24' -o vmbr0 -j MASQUERADE
        post-down iptables -t nat -D POSTROUTING -s '10.240.0.0/24' -o vmbr0 -j MASQUERADE
$ cat /etc/systemd/network/50-default.network
# This file sets the IP configuration of the primary (public) network device.
# You can also see this as "OSI Layer 3" config.
# It was created by the OVH installer, please be careful with modifications.
# Documentation: man systemd.network or https://www.freedesktop.org/software/systemd/man/systemd.network.html

[Match]
Name=vmbr0

[Network]
Description=network interface on public network, with default route
DHCP=no
Address=${HST_IP}/24
Gateway=${HST_GTW_IP}
IPv6AcceptRA=no
NTP=ntp.ovh.net
DNS=127.0.0.1
DNS=8.8.8.8

[Address]
Address=${HST_IPv6}

[Route]
Destination=2001:0000:0000:34ff:ff:ff:ff:ff
Scope=link
$ cat /etc/systemd/network/50-public-interface.link
# This file configures the relation between network device and device name.
# You can also see this as "OSI Layer 2" config.
# It was created by the OVH installer, please be careful with modifications.
# Documentation: man systemd.link or https://www.freedesktop.org/software/systemd/man/systemd.link.html

[Match]
Name=vmbr0

[Link]
Description=network interface on public network, with default route
MACAddressPolicy=persistent
NamePolicy=kernel database onboard slot path mac
#Name=eth0	# name under which this interface is known under OVH rescue system
#Name=eno1	# name under which this interface is probably known by systemd
```

## Get the latest CentOS templates
* Download the latest template from the
  [Linux containers site](https://us.images.linuxcontainers.org/images/centos/7/amd64/default/)
  (change the date and time-stamp according to the time you download that
  template):
```bash
$ wget https://us.images.linuxcontainers.org/images/centos/7/amd64/default/20190510_07:08/rootfs.tar.xz -O /vz/template/cache/centos-7-default_20190510_amd64.tar.xz
```

## Kubernetes cluster gateway
* Create the LXC template for the Kubernetes cluster gateway:
```bash
$ pct create 103 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 1 --hostname gwkublxc.example.com --memory 1024 --swap 2048 --net0 name=eth0,bridge=vmbr0,firewall=1,gw=${HST_GTW_IP},hwaddr=${GTW_MAC},ip=${GTW_IP}/32,type=veth --net1 name=eth1,bridge=vmbr3,ip=10.240.0.103/24,type=veth --onboot 1 --ostype centos
```

* Enter the gateway and complement the installation
  (for security reason, it may be a good idea to change the SSH port
  from `22` to, say `7022`):
```bash
$ pct start 103
$ pct enter 103
# yum -y update
# yum -y install openssh-server man-db file rsync openssl wget curl less htop yum-utils net-tools
# sed -ie 's/#Port 22/Port 7022/g' /etc/ssh/sshd_config
# systemctl restart sshd && systemctl enable sshd
```

* Settings:
```bash
$ cat >> /etc/hosts << _EOF

# Kubernetes on LXC
10.240.0.11     etcd1.example.com       etcd1
10.240.0.12     etcd2.example.com       etcd2
10.240.0.20     controller.example.com  controller
10.240.0.21     controller1.example.com controller1
10.240.0.22     controller2.example.com controller2
10.240.0.31     worker1.example.com     worker1
10.240.0.32     worker2.example.com     worker2
10.240.0.40     lb.example.com          lb
10.240.0.41     lb1.example.com         lb1
10.240.0.42     lb2.example.com         lb2

_EOF
$ cat >> ~/.bashrc << _EOF

# Kubernetes
export KUBERNETES_PUBLIC_IP_ADDRESS="10.240.0.20"

# Source aliases
if [ -f ~/.bash_aliases ]
then
        . ~/.bash_aliases
fi

_EOF
$ cat ~/.bash_alises << _EOF
# User specific aliases and functions
alias dir='ls -laFh --color'
alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'

_EOF
$ . ~/.bashrc
```

## CFSSL
* CFSSL software:
```bash
$ mkdir -p /opt/cfssl
$ wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 -O /opt/cfssl/cfssl_linux-amd64
$ wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 -O /opt/cfssl/cfssljson_linux-amd64
$ chmod +x /opt/cfssl/cfssl_linux-amd64 /opt/cfssl/cfssljson_linux-amd64
$ install /opt/cfssl/cfssl_linux-amd64 /usr/local/bin/cfssl
$ install /opt/cfssl/cfssljson_linux-amd64 /usr/local/bin/cfssljson
```

* CA certificates:
```bash
$ mkdir -p /opt/cfssl/etc && cd /opt/cfssl/etc
$ cat > /opt/cfssl/etc/ca-config.json << _EOF
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "kubernetes": {
        "usages": ["signing", "key encipherment", "server auth", "client auth"],
        "expiry": "8760h"
      }
    }
  }
}
_EOF
cat > /opt/cfssl/etc/ca-csr.json << _EOF
{
  "CN": "Kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "NO",
      "L": "Oslo",
      "O": "Kubernetes",
      "OU": "CA",
      "ST": "Oslo"
    }
  ]
}
_EOF
$ cfssl gencert -initca /opt/cfssl/etc/ca-csr.json | cfssljson -bare ca
2019/05/11 14:39:26 [INFO] generating a new CA key and certificate from CSR
2019/05/11 14:39:26 [INFO] generate received request
2019/05/11 14:39:26 [INFO] received CSR
2019/05/11 14:39:26 [INFO] generating key: rsa-2048
2019/05/11 14:39:26 [INFO] encoded CSR
2019/05/11 14:39:26 [INFO] signed certificate with serial number 53..53
$ openssl x509 -in /opt/cfssl/etc/ca.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5d:..:71
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=NO, ST=Oslo, L=Oslo, O=Kubernetes, OU=CA, CN=Kubernetes
        Validity
            Not Before: May 11 12:34:00 2019 GMT
            Not After : May  9 12:34:00 2024 GMT
        Subject: C=NO, ST=Oslo, L=Oslo, O=Kubernetes, OU=CA, CN=Kubernetes
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:e1:42:3b:8b:96:81:bf:3a:00:80:17:8c:8e:48:
					...
                    d8:99
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:2
            X509v3 Subject Key Identifier: 
                3B:3D:FA:5A:CA:4D:7E:5A:66:72:92:34:0D:9D:CB:E8:38:C3:99:86
            X509v3 Authority Key Identifier: 
                keyid:3B:3D:FA:3A:CA:7D:7E:5A:66:72:92:34:0D:9D:CB:E8:38:C3:99:86

    Signature Algorithm: sha256WithRSAEncryption
         c5:fa:d8:50:f7:ec:13:f1:2c:68:d5:dd:c9:67:b9:d9:47:cd:
		 ...
         37:93:6e:fd
```

* Node certificates:
```bash
$ cat > /opt/cfssl/etc/kubernetes-csr.json <<EOF
{
  "CN": "*.example.com",
  "hosts": [
    "10.32.0.1",
    "etcd1",
    "etcd2",
    "etcd1.example.com",
    "etcd2.example.com",
    "10.240.0.11",
    "10.240.0.12",
    "controller1",
    "controller2",
    "controller1.example.com",
    "controller2.example.com",
    "10.240.0.21",
    "10.240.0.22",
    "worker1",
    "worker2",
    "worker3",
    "worker4",
    "worker1.example.com",
    "worker2.example.com",
    "worker3.example.com",
    "worker4.example.com",
    "10.240.0.31",
    "10.240.0.32",
    "10.240.0.33",
    "10.240.0.34",
    "controller.example.com",
    "kubernetes.example.com",
    "${KUBERNETES_PUBLIC_IP_ADDRESS}",
    "lb",
    "lb1",
    "lb2",
    "lb.example.com",
    "lb1.example.com",
    "lb2.example.com",
    "10.240.0.40",
    "10.240.0.41",
    "10.240.0.42",
    "gwkublxc",
    "gwkublxc.example.com",
    "10.240.0.103",
    "147.135.185.243",
    "localhost",
    "127.0.0.1"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "NO",
      "L": "Oslo",
      "O": "Kubernetes",
      "OU": "Cluster",
      "ST": "Oslo"
    }
  ]
}
EOF
$ cfssl gencert \
  -ca=/opt/cfssl/etc/ca.pem \
  -ca-key=/opt/cfssl/etc/ca-key.pem \
  -config=/opt/cfssl/etc/ca-config.json \
  -profile=kubernetes \
  /opt/cfssl/etc/kubernetes-csr.json | cfssljson -bare kubernetes
2019/05/11 15:48:07 [INFO] generate received request
2019/05/11 15:48:07 [INFO] received CSR
2019/05/11 15:48:07 [INFO] generating key: rsa-2048
2019/05/11 15:48:07 [INFO] encoded CSR
2019/05/11 15:48:07 [INFO] signed certificate with serial number 31..24
2019/05/11 15:48:07 [WARNING] This certificate lacks a "hosts" field. This makes it unsuitable for
websites. For more information see the Baseline Requirements for the Issuance and Management
of Publicly-Trusted Certificates, v.1.1.6, from the CA/Browser Forum (https://cabforum.org);
specifically, section 10.2.3 ("Information Requirements").
$ openssl x509 -in /opt/cfssl/etc/kubernetes.pem -text -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            37:79:27:bc:bf:35:e8:f7:40:58:f9:03:73:ac:38:86:18:bd:ee:68
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=NO, ST=Oslo, L=Oslo, O=Kubernetes, OU=CA, CN=Kubernetes
        Validity
            Not Before: May 11 13:43:00 2019 GMT
            Not After : May 10 13:43:00 2020 GMT
        Subject: C=NO, ST=Oslo, L=Oslo, O=Kubernetes, OU=Cluster, CN=*.example.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d9:49:54:5d:4b:81:55:20:13:ff:61:a3:a3:79:
					...
                    5a:95
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                A6:3F:76:BE:4E:C1:42:6E:43:F2:13:79:A1:B8:54:0D:B8:BB:48:C2
            X509v3 Authority Key Identifier: 
                keyid:3B:5D:FA:5A:CA:7D:7E:5A:66:72:92:34:0D:9D:CB:E8:38:C3:99:86

            X509v3 Subject Alternative Name: 
                DNS:etcd1, ..., DNS:localhost, IP Address:10.32.0.1, ..., IP Address:127.0.0.1
    Signature Algorithm: sha256WithRSAEncryption
         c9:ad:3a:16:c7:8c:56:f0:9a:ec:4c:77:72:18:c7:26:34:ae:
		 ...
         ae:84:75:d7
```

# `etcd`
* `etcd1`:
```bash
$ pct create 211 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 1 --hostname etcd1.example.com --memory 1024 --swap 2048 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.11/24,type=veth --onboot 1 --ostype centos
$ pct resize 211 rootfs 10G
$ pce enter 211
# yum -y install net-tools openssh-server
# systemctl start sshd && systemctl enable sshd
# exit
```

* `etcd2`:
```bash
$ pct create 212 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 1 --hostname etcd2.example.com --memory 1024 --swap 2048 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.12/24,type=veth --onboot 1 --ostype centos
$ pct resize 212 rootfs 10G
$ pce enter 212
# yum -y install net-tools openssh-server
# systemctl start sshd && systemctl enable sshd
# exit
```

### `controller`
* `controller`:
```bash
$ pct create 220 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 2 --hostname controller.example.com --memory 2048 --swap 4096 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.20/24,type=veth --onboot 1 --ostype centos
$ pct resize 220 rootfs 10G
```

* `controller1`:
```bash
$ pct create 221 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 2 --hostname controller1.example.com --memory 2048 --swap 4096 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.21/24,type=veth --onboot 1 --ostype centos
$ pct resize 221 rootfs 10G
```

* `controller2`:
```bash
$ pct create 222 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 2 --hostname controller2.example.com --memory 2048 --swap 4096 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.22/24,type=veth --onboot 1 --ostype centos
$ pct resize 222 rootfs 10G
```

# `worker`
* `worker1`:
```bash
$ pct create 231 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 8 --hostname worker1.example.com --memory 16384 --swap 16384 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.31/24,type=veth --onboot 1 --ostype centos
$ pct resize 231 rootfs 20G
```

* `worker2`:
```bash
$ pct create 232 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 8 --hostname worker2.example.com --memory 16384 --swap 16384 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.32/24,type=veth --onboot 1 --ostype centos
$ pct resize 232 rootfs 20G
```

# `lb`
* `lb`:
```bash
$ pct create 240 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 1 --hostname lb.example.com --memory 512 --swap 1024 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.40/24,type=veth --onboot 1 --ostype centos
$ # pct resize 240 rootfs 4G
```

* `lb1`:
```bash
$ pct create 241 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 1 --hostname lb1.example.com --memory 512 --swap 1024 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.41/24,type=veth --onboot 1 --ostype centos
$ # pct resize 241 rootfs 4G
```

* `lb2`:
```bash
$ pct create 242 local:vztmpl/centos-7-default_20190510_amd64.tar.xz --arch amd64 --cores 1 --hostname lb2.example.com --memory 512 --swap 1024 --net0 name=eth0,bridge=vmbr3,gw=10.240.0.2,ip=10.240.0.42/24,type=veth --onboot 1 --ostype centos
$ # pct resize 242 rootfs 4G
```

# On the clients
* SSH configuration:
```bash
$ cat >> ~/.ssh/config << _EOF

# Kubernetes cluster on Proxmox/LXC
Host gw.kublxc
  HostName gwkublxc.example.com
  Port 7022
Host etcd1
  HostName etcd1.example.com
  ProxyCommand ssh -W %h:22 root@gw.kublxc
Host etcd2
  HostName etcd2.example.com
  ProxyCommand ssh -W %h:22 root@gw.kublxc
Host controller
   HostName controller.example.com
   ProxyCommand ssh -W %h:22 root@gw.kublxc
Host controller1
   HostName controller1.example.com
   ProxyCommand ssh -W %h:22 root@gw.kublxc
Host controller2
   HostName controller2.example.com
   ProxyCommand ssh -W %h:22 root@gw.kublxc
Host worker1
  HostName worker1.example.com
  ProxyCommand ssh -W %h:22 root@gw.kublxc
Host worker2
  HostName worker2.example.com
  ProxyCommand ssh -W %h:22 root@gw.kublxc
Host lb
  HostName lb.example.com
  ProxyCommand ssh -W %h:22 root@gw.kublxc
Host lb1
  HostName lb1.example.com
  ProxyCommand ssh -W %h:22 root@gw.kublxc
Host lb2
  HostName lb2.example.com
  ProxyCommand ssh -W %h:22 root@gw.kublxc

_EOF
```

* Upload the SSH keys onto the K8S gateway:
```bash
$ rsync -av your-ssh-keys root@gw.kublxc:~/.ssh/
```

* Push the certificates to every K8S node:
```bash
$ chmod 644 /opt/cfssl/etc/kubernetes-key.pem
$ declare -a node_list=("lb" "lb1" "lb2" "etcd1" "etcd2" "controller" "controller1" "controller2" "worker1" "worker2")
$ declare -a cert_list=("/opt/cfssl/etc/ca.pem" "/opt/cfssl/etc/kubernetes-key.pem" "/opt/cfssl/etc/kubernetes.pem")
$ for node in "${node_list[@]}"
do
  for cert in "${cert_list[@]}"
  do
    rsync -av ${cert} root@${node}:/root/
  done
done
```

# Kubernetes - Supplementary configuration
* General:
```bash
$ yum -y update && \
 yum -y install epel-release && \
 yum -y install rpmconf yum-utils htop wget less net-tools whois bzip2 rsync \
   bash-completion bash-completion-extras openssh-server ntp
$ rpmconf -a
$ ln -sf /usr/share/zoneinfo/Europe/Paris /etc/localtime && \
 systemctl start ntpd && systemctl enable ntpd && \
 setenforce 0 && \
 sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
```

* SSH:
```bash
$ mkdir ~/.ssh && chmod 700 ~/.ssh && \
 cat >> ~/.ssh/authorized_keys << _EOF
ssh-rsa AAAZZZ k8s@example.com
_EOF
$ chmod 600 ~/.ssh/authorized_keys
$ systemctl start sshd.service && systemctl enable sshd.service
# Check that you can connect from outside, beginning by the Proxmox host
$ passwd -d root
```

* Check that the firewalls are not installed:
```bash
$ systemctl status firewalld.service && systemctl stop firewalld.service && systemctl disable firewalld.service
$ systemctl status iptables.service
```

* Set the `/etc/hosts` file:
```bash
$ cat > /etc/hosts << _EOF
# Local VM
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

# Kubernetes on LXC
10.240.0.11     etcd1.example.com       etcd1
10.240.0.12     etcd2.example.com       etcd2
10.240.0.20     controller.example.com  controller
10.240.0.21     controller1.example.com controller1
10.240.0.22     controller2.example.com controller2
10.240.0.31     worker1.example.com     worker1
10.240.0.32     worker2.example.com     worker2
10.240.0.40     lb.example.com          lb
10.240.0.41     lb1.example.com         lb1
10.240.0.42     lb2.example.com         lb2

_EOF
```

### Checks
* On the host:
```bash
$ declare -a node_list=("lb" "lb1" "lb2" "etcd1" "etcd2" "controller" "controller1" "controller2" "worker1" "worker2")
$ for node in "${node_list[@]}"; do ssh root@${node} "hostname; getenforce"; done
etcd1.example.com
Disabled
etcd2.example.com
Disabled
controller1.example.com
Disabled
controller2.example.com
Disabled
worker1.example.com
Disabled
worker2.example.com
Disabled
```

### `etcd` setup
* Setup and start `etcd` on all the etcd cluster nodes:
```bash
$ mkdir -p /opt/etcd && cat > /opt/etcd/etcd.service << _EOF
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
WorkingDirectory=/var/lib/etcd/
EnvironmentFile=-/etc/etcd/etcd.conf
User=etcd
# set GOMAXPROCS to number of processors
ExecStart=/bin/bash -c "GOMAXPROCS=\$(nproc) /usr/bin/etcd \
  --name=\"\${ETCD_NAME}\" \
  --data-dir=\"\${ETCD_DATA_DIR}\" \
  --cert-file=\"/etc/etcd/kubernetes.pem\" \
  --key-file=\"/etc/etcd/kubernetes-key.pem\" \
  --peer-cert-file=\"/etc/etcd/kubernetes.pem\" \
  --peer-key-file=\"/etc/etcd/kubernetes-key.pem\" \
  --trusted-ca-file=\"/etc/etcd/ca.pem\" \
  --peer-trusted-ca-file=\"/etc/etcd/ca.pem\" \
  --initial-advertise-peer-urls=\"https://INTERNAL_IP:2380\" \
  --listen-peer-urls=\"https://INTERNAL_IP:2380\" \
  --listen-client-urls=\"https://INTERNAL_IP:2379,http://127.0.0.1:2379\" \
  --advertise-client-urls=\"https://INTERNAL_IP:2379\" \
  --initial-cluster-token=\"etcd-cluster-0\" \
  --initial-cluster=\"etcd1=https://10.240.0.11:2380,etcd2=https://10.240.0.12:2380\" \
  --initial-cluster-state=\"new\""
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
_EOF
$ declare -a nodeip_list=("10.240.0.11" "10.240.0.12")
$ declare -a node_list=("etcd1" "etcd2")
$ for node in "${node_list[@]}"; do ssh root@${node} "mkdir -p /etc/etcd/ && mv ca.pem kubernetes-key.pem kubernetes.pem /etc/etcd/"; done
$ for node in "${node_list[@]}"; do ssh root@${node} "yum -y install etcd file"; done
$ for node in "${node_list[@]}"; do rsync -av -p /opt/etcd/etcd.service root@${node}:/usr/lib/systemd/system/; done
$ for nodeip in "${nodeip_list[@]}"; do ssh root@${nodeip} "sed -ie s/INTERNAL_IP/${nodeip}/g /usr/lib/systemd/system/etcd.service"; done
```

* Check the setup:
```bash
$ ssh etcd1
# systemctl status etcd --no-pager
# netstat -antlp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 10.240.0.11:2379        0.0.0.0:*               LISTEN      4746/etcd           
tcp        0      0 127.0.0.1:2379          0.0.0.0:*               LISTEN      4746/etcd           
tcp        0      0 10.240.0.11:2380        0.0.0.0:*               LISTEN      4746/etcd           
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      266/sshd            
tcp        0      0 127.0.0.1:40872         127.0.0.1:2379          ESTABLISHED 4746/etcd           
tcp        0      0 10.240.0.11:22          10.240.0.103:42792      ESTABLISHED 4419/sshd: root@pts 
tcp        0      0 10.240.0.11:39722       10.240.0.11:2379        ESTABLISHED 4746/etcd           
tcp        0      0 10.240.0.11:2379        10.240.0.11:39722       ESTABLISHED 4746/etcd           
tcp        0      0 127.0.0.1:2379          127.0.0.1:40872         ESTABLISHED 4746/etcd           
tcp6       0      0 :::22                   :::*                    LISTEN      266/sshd            
# etcdctl --ca-file=/etc/etcd/ca.pem cluster-health
member 8e9e05c52164694d is healthy: got healthy result from https://10.240.0.11:2379
cluster is healthy
# etcdctl cluster-health
failed to check the health of member 8e9e05c52164694d on https://10.240.0.11:2379: Get https://10.240.0.11:2379/health: x509: certificate signed by unknown authority
member 8e9e05c52164694d is unreachable: [https://10.240.0.11:2379] are all unreachable
cluster is unavailable
# exit
$ ssh etcd2
# netstat -antlp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 10.240.0.12:2379        0.0.0.0:*               LISTEN      1179/etcd           
tcp        0      0 127.0.0.1:2379          0.0.0.0:*               LISTEN      1179/etcd           
tcp        0      0 10.240.0.12:2380        0.0.0.0:*               LISTEN      1179/etcd           
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      389/sshd            
tcp        0      0 127.0.0.1:2379          127.0.0.1:40864         ESTABLISHED 1179/etcd           
tcp        0      0 127.0.0.1:40864         127.0.0.1:2379          ESTABLISHED 1179/etcd           
tcp        0      0 10.240.0.12:22          10.240.0.103:58082      ESTABLISHED 635/sshd: root@pts/ 
tcp        0      0 10.240.0.12:2379        10.240.0.12:60890       ESTABLISHED 1179/etcd           
tcp        0      0 10.240.0.12:60890       10.240.0.12:2379        ESTABLISHED 1179/etcd           
tcp6       0      0 :::22                   :::*                    LISTEN      389/sshd            
# etcdctl --ca-file=/etc/etcd/ca.pem cluster-health
member 8e9e05c52164694d is healthy: got healthy result from https://10.240.0.12:2379
cluster is healthy
# etcdctl cluster-health
failed to check the health of member 8e9e05c52164694d on https://10.240.0.12:2379: Get https://10.240.0.12:2379/health: x509: certificate signed by unknown authority
member 8e9e05c52164694d is unreachable: [https://10.240.0.12:2379] are all unreachable
cluster is unavailable
```

### Kubernetes API, Controller and Scheduler Servers
* On the LXC K8S gateway, download Kubernetes:
```bash
$ K8S_VER=$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)
$ echo $K8S_VER 
v1.14.1
$ declare -a kubbin_list=("kube-apiserver" "kube-controller-manager" "kube-scheduler" "kubectl")
$ for kubbin in "${kubbin_list[@]}"; do curl -LO https://storage.googleapis.com/kubernetes-release/release/${K8S_VER}/bin/linux/amd64/${kubbin} && chmod +x ${kubbin} && mv ${kubbin} /usr/local/bin/; done
$ mkdir -p /var/lib/kubernetes && cat > /var/lib/kubernetes/token.csv << _EOF
cat token.csv 
chAng3m3,admin,admin
chAng3m3,scheduler,scheduler
chAng3m3,kubelet,kubelet
_EOF
```

* Upload the Kubernetes binaries to all the nodes:
```bash
$ declare -a nodeip_list=("10.240.0.20" "10.240.0.21" "10.240.0.22")
$ declare -a node_list=("controller" "controller1" "controller2")
$ declare -a node_ext_list=("lb" "lb1" "lb2" "etcd1" "etcd2" "controller" "controller1" "controller2" "worker1" "worker2")
$ for node in "${node_list[@]}"; do ssh root@${node} "yum -y install file less man-db htop"; done
$ for node in "${node_list[@]}"; do ssh root@${node} "mkdir -p /var/lib/kubernetes/ && mv ca.pem kubernetes-key.pem kubernetes.pem /var/lib/kubernetes/"; done
$ for node in "${node_ext_list[@]}"; do rsync -av -p /usr/local/bin/kube* root@${node}:/usr/local/bin/; done
$ for node in "${node_ext_list[@]}"; do rsync -av -p /var/lib/kubernetes/token.csv root@${node}:/var/lib/kubernetes/; done
```

