# 一：基础环境：

基于kubeadm和cri-dockerd使用docker运行时部署K8S 集群

部署环境操作系统： ubuntu 22.04.x/ubuntu 24.04.x

```bash
LB：
172.31.7.109
172.31.7.110

VIP: 172.31.7.118

master/etcd节点(etcd与master节点复用):
	k8s-master1 172.31.7.101
	k8s-master2 172.31.7.102
	k8s-master3 172.31.7.103
	
worker/node 节点： 
	k8s-node1  	172.31.7.111
	k8s-node2		172.31.7.112
	k8s-node3		172.31.7.113

Image Registry(Harbor):
  172.31.7.104
```

![image-20240910093009760](images/image-20240910093009760.png)

## 1.1：安装负载均衡：

```bash
root@k8s-ha1:~# apt install keepalived  haproxy
root@k8s-ha1:~# cd /etc/keepalived/
root@k8s-ha1:/etc/keepalived# cat keepalived.conf
vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass 1111
    }
    virtual_ipaddress {
        172.31.7.188 dev eth0 label eth0:1
        172.31.7.189 dev eth0 label eth0:2
        172.31.7.190 dev eth0 label eth0:3
        172.31.7.191 dev eth0 label eth0:4
    }
root@k8s-ha1:/etc/keepalived# systemctl   restart  keepalived.service
root@k8s-ha1:/etc/keepalived# ifconfig 
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.7.109  netmask 255.255.248.0  broadcast 172.31.7.255
        inet6 fe80::20c:29ff:fe80:e083  prefixlen 64  scopeid 0x20<link>
        ether 00:0c:29:80:e0:83  txqueuelen 1000  (Ethernet)
        RX packets 700  bytes 79229 (79.2 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 427  bytes 84331 (84.3 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0:1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.7.188  netmask 255.255.255.255  broadcast 0.0.0.0
        ether 00:0c:29:80:e0:83  txqueuelen 1000  (Ethernet)

eth0:2: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.7.189  netmask 255.255.255.255  broadcast 0.0.0.0
        ether 00:0c:29:80:e0:83  txqueuelen 1000  (Ethernet)

eth0:3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.7.190  netmask 255.255.255.255  broadcast 0.0.0.0
        ether 00:0c:29:80:e0:83  txqueuelen 1000  (Ethernet)

eth0:4: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.31.7.191  netmask 255.255.255.255  broadcast 0.0.0.0
        ether 00:0c:29:80:e0:83  txqueuelen 1000  (Ethernet)


#HAProxy 配置
root@k8s-ha1:~# cd /etc/haproxy/
root@k8s-ha1:/etc/haproxy# cat haproxy.cfg 
listen k8s-6443
    bind 172.31.7.188:6443
    mode tcp
    server server1 172.31.7.101:6443 check inter 3s  rise 3 fall 3
root@k8s-ha1:/etc/haproxy# systemctl  restart  haproxy.service 
```

## 1.2：安装docker：

各master节点及node节点安装docker：

```bash
root@k8s-master1:/usr/local/src# tar xvf runtime-docker_24.0.9-containerd_1.7.20-binary-install.tar.gz 
root@k8s-master1:/usr/local/src# bash runtime-install.sh  docker

root@k8s-master2:/usr/local/src# runtime-docker_24.0.9-containerd_1.7.20-binary-install.tar.gz 

root@k8s-master2:/usr/local/src# bash runtime-install.sh  docker


root@k8s-master3:/usr/local/src# runtime-docker_24.0.9-containerd_1.7.20-binary-install.tar.gz 

root@k8s-master3:/usr/local/src# bash runtime-install.sh  docker



root@k8s-node1:/usr/local/src# tar xvf tar xvf runtime-docker24.0.2-containerd1.6.21-binary-install.tar.gz
root@k8s-node1:/usr/local/src# bash runtime-install.sh  docker

root@k8s-node2:/usr/local/src# tar xvf tar xvf runtime-docker24.0.2-containerd1.6.21-binary-install.tar.gz
root@k8s-node2:/usr/local/src# bash runtime-install.sh  docker

root@k8s-node3:/usr/local/src# tar xvf tar xvf runtime-docker24.0.2-containerd1.6.21-binary-install.tar.gz
root@k8s-node3:/usr/local/src# bash runtime-install.sh  docker

#各节点自定义containerd中初始化镜像和Cgroup配置：
root@k8s-master1:~# mkdir  /etc/containerd
root@k8s-master1:~# containerd config default > /etc/containerd/config.toml
root@k8s-master1:~# vim /etc/containerd/config.toml
65     sandbox_image = "registry.cn-hangzhou.aliyuncs.com/google_containers/pause:3.9"
137             SystemdCgroup = true

root@k8s-master1:~# scp /etc/containerd/config.toml  172.31.7.102:/etc/containerd/config.toml
root@k8s-master1:~# scp /etc/containerd/config.toml  172.31.7.103:/etc/containerd/config.toml
root@k8s-master1:~# scp /etc/containerd/config.toml  172.31.7.111:/etc/containerd/config.toml
root@k8s-master1:~# scp /etc/containerd/config.toml  172.31.7.112:/etc/containerd/config.toml
root@k8s-master1:~# scp /etc/containerd/config.toml  172.31.7.113:/etc/containerd/config.toml
```

## 1.3：安装cri-dockerd：

```bash
root@k8s-master1:~# tar xvf cri-dockerd-0.3.15.amd64.tgz 
cri-dockerd/
cri-dockerd/cri-dockerd

root@k8s-master1:~# cp cri-dockerd/cri-dockerd  /usr/local/bin/


root@k8s-master1:~# cat > /etc/systemd/system/cri-dockerd.service<<"EOF"
[Unit]
Description=CRI Interface for Docker Application Container Engine
Documentation=https://docs.mirantis.com
After=network-online.target firewalld.service docker.service
Wants=network-online.target
Requires=cri-dockerd.socket

[Service]
Type=notify
ExecStart=/usr/local/bin/cri-dockerd --container-runtime-endpoint fd:// --pod-infra-container-image=registry.aliyuncs.com/google_containers/pause:3.9
ExecReload=/bin/kill -s HUP $MAINPID
TimeoutSec=0
RestartSec=2
Restart=always
StartLimitBurst=3
StartLimitInterval=60s
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process

[Install]
WantedBy=multi-user.target
EOF


root@k8s-master1:~# cat > /etc/systemd/system/cri-dockerd.socket <<"EOF"
[Unit]
Description=CRI Docker Socket for the API
PartOf=cri-dockerd.service

[Socket]
ListenStream=%t/cri-dockerd.sock
SocketMode=0660
SocketUser=root
SocketGroup=docker

[Install]
WantedBy=sockets.target
EOF

root@k8s-master1:~# systemctl daemon-reload && systemctl enable cri-dockerd.service && systemctl  enable cri-dockerd.socket && systemctl status cri-dockerd.service

root@k8s-master1:~# scp /usr/local/bin/cri-dockerd  172.31.7.102:/usr/local/bin/
root@k8s-master1:~# scp /usr/local/bin/cri-dockerd  172.31.7.103:/usr/local/bin/
root@k8s-master1:~# scp /usr/local/bin/cri-dockerd  172.31.7.111:/usr/local/bin/
root@k8s-master1:~# scp /usr/local/bin/cri-dockerd  172.31.7.112:/usr/local/bin/
root@k8s-master1:~# scp /usr/local/bin/cri-dockerd  172.31.7.113:/usr/local/bin/


root@k8s-master1:~# scp /etc/systemd/system/cri-dockerd.service /etc/systemd/system/cri-dockerd.socket 172.31.7.102:/etc/systemd/system
root@k8s-master1:~# scp /etc/systemd/system/cri-dockerd.service /etc/systemd/system/cri-dockerd.socket 172.31.7.103:/etc/systemd/system
root@k8s-master1:~# scp /etc/systemd/system/cri-dockerd.service /etc/systemd/system/cri-dockerd.socket 172.31.7.111:/etc/systemd/system
root@k8s-master1:~# scp /etc/systemd/system/cri-dockerd.service /etc/systemd/system/cri-dockerd.socket 172.31.7.112:/etc/systemd/system
root@k8s-master1:~# scp /etc/systemd/system/cri-dockerd.service /etc/systemd/system/cri-dockerd.socket 172.31.7.113:/etc/systemd/system

root@k8s-master2:~# systemctl daemon-reload && systemctl enable cri-dockerd.service && systemctl  enable cri-dockerd.socket && systemctl status cri-dockerd.service
root@k8s-master3:~# systemctl daemon-reload && systemctl enable cri-dockerd.service && systemctl  enable cri-dockerd.socket && systemctl status cri-dockerd.service

root@k8s-node1:~# systemctl daemon-reload && systemctl enable cri-dockerd.service && systemctl  enable cri-dockerd.socket && systemctl status cri-dockerd.service
root@k8s-node2:~# systemctl daemon-reload && systemctl enable cri-dockerd.service && systemctl  enable cri-dockerd.socket && systemctl status cri-dockerd.service
root@k8s-node3:~# systemctl daemon-reload && systemctl enable cri-dockerd.service && systemctl  enable cri-dockerd.socket && systemctl status cri-dockerd.service
```



## 1.3：安装kubeadm、kubectl、kubelet：

各master与node安装kubeadm与kubelet、在需要执行kubectl 命令行管理命令的节点安装kubectl

https://mirrors.aliyun.com/kubernetes-new/core/stable/ #当前支持的版本

各master与node节点：

```bash
#安装apt-transport-https支持https仓库
root@k8s-master1:~# apt-get update && apt-get install -y apt-transport-https

#导入GPG证书、目前各版本的GPG证书通用的
root@k8s-master1:~# curl -fsSL https://mirrors.aliyun.com/kubernetes-new/core/stable/v1.30/deb/Release.key |
    gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

#添加指定版本的kubernetes apt源
root@k8s-master1:~#   echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://mirrors.aliyun.com/kubernetes-new/core/stable/v1.30/deb/ /" |
    tee /etc/apt/sources.list.d/kubernetes.list

#更新apt源
root@k8s-master1:~# apt update

#验证版本
root@k8s-master1:~# apt-cache  madison kubeadm
   kubeadm | 1.30.4-1.1 | https://mirrors.aliyun.com/kubernetes-new/core/stable/v1.30/deb  Packages
   kubeadm | 1.30.3-1.1 | https://mirrors.aliyun.com/kubernetes-new/core/stable/v1.30/deb  Packages
   kubeadm | 1.30.2-1.1 | https://mirrors.aliyun.com/kubernetes-new/core/stable/v1.30/deb  Packages
   kubeadm | 1.30.1-1.1 | https://mirrors.aliyun.com/kubernetes-new/core/stable/v1.30/deb  Packages
   kubeadm | 1.30.0-1.1 | https://mirrors.aliyun.com/kubernetes-new/core/stable/v1.30/deb  Packages

#执行安装
root@k8s-master1:~# apt-get install -y kubeadm=1.30.1-1.1 kubectl=1.30.1-1.1 kubelet=1.30.1-1.1
root@k8s-master2:~# apt-get install -y kubeadm=1.30.1-1.1 kubectl=1.30.1-1.1 kubelet=1.30.1-1.1
root@k8s-master3:~# apt-get install -y kubeadm=1.30.1-1.1 kubectl=1.30.1-1.1 kubelet=1.30.1-1.1

root@k8s-node1:~# apt-get install -y kubeadm=1.30.1-1.1 kubectl=1.30.1-1.1 kubelet=1.30.1-1.1
root@k8s-node2:~# apt-get install -y kubeadm=1.30.1-1.1 kubectl=1.30.1-1.1 kubelet=1.30.1-1.1
root@k8s-node3:~# apt-get install -y kubeadm=1.30.1-1.1 kubectl=1.30.1-1.1 kubelet=1.30.1-1.1
```

## 1.4：下载kubenetes 需要容器镜像镜像:

```bash
root@k8s-master1:~# kubeadm config images list --kubernetes-version v1.30.1
registry.k8s.io/kube-apiserver:v1.30.1
registry.k8s.io/kube-controller-manager:v1.30.1
registry.k8s.io/kube-scheduler:v1.30.1
registry.k8s.io/kube-proxy:v1.30.1
registry.k8s.io/coredns/coredns:v1.11.1
registry.k8s.io/pause:3.9
registry.k8s.io/etcd:3.5.12-0


#替换镜像仓库下载容器镜像
root@k8s-master2:~# kubeadm config images pull --kubernetes-version v1.30.1 --image-repository registry.cn-hangzhou.aliyuncs.com/google_containers --cri-socket /var/run/cri-dockerd.sock  #直接下载镜像或使用下一步骤的脚本下载、不指定--cri-socket 会使用containerd

root@k8s-master1:~# cat image-down.sh 
#!/bin/bash
docker pull registry.cn-hangzhou.aliyuncs.com/google_containers/kube-apiserver:v1.30.1
docker pull registry.cn-hangzhou.aliyuncs.com/google_containers/kube-controller-manager:v1.30.1
docker pull registry.cn-hangzhou.aliyuncs.com/google_containers/kube-scheduler:v1.30.1
docker pull registry.cn-hangzhou.aliyuncs.com/google_containers/kube-proxy:v1.30.1
docker pull registry.cn-hangzhou.aliyuncs.com/google_containers/coredns:v1.11.1
docker pull registry.cn-hangzhou.aliyuncs.com/google_containers/pause:3.9
docker pull registry.cn-hangzhou.aliyuncs.com/google_containers/etcd:3.5.12-0

root@k8s-master1:~# bash image-download.sh 
```

## 1.5：系统内核参数优化：

```bash
root@k8s-master1:~# cat /etc/sysctl.conf
###################################################################
net.ipv4.ip_forward=1
vm.max_map_count=262144
kernel.pid_max=4194303
fs.file-max=1000000
net.ipv4.tcp_max_tw_buckets=6000
net.netfilter.nf_conntrack_max=2097152

net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
vm.swappiness=0

内核模块开机挂载：
root@k8s-master1:~# vim /etc/modules-load.d/modules.conf 
ip_vs
ip_vs_lc
ip_vs_lblc
ip_vs_lblcr
ip_vs_rr
ip_vs_wrr
ip_vs_sh
ip_vs_dh
ip_vs_fo
ip_vs_nq
ip_vs_sed
ip_vs_ftp
ip_vs_sh
ip_tables
ip_set
ipt_set
ipt_rpfilter
ipt_REJECT
ipip
xt_set
br_netfilter
nf_conntrack
overlay

#各节点重启后验证内核模块与内存参数：
root@k8s-master1:~# reboot
root@k8s-master1:~# lsmod  | grep br_netfilter
br_netfilter           32768  0
bridge                307200  1 br_netfilter
root@k8s-master1:~# sysctl  -a | grep bridge-nf-call-iptables
net.bridge.bridge-nf-call-iptables = 1
```

## 1.6：kubernetes集群初始化：

#如开启swap分区的报错
command failed" err="failed to run Kubelet: running with swap on is not supported, please disable swap! or set --fail-swap-on flag to false

#配置 kubelet 的 cgroup 驱动

https://kubernetes.io/zh-cn/docs/tasks/administer-cluster/kubeadm/configure-cgroup-driver/#configuring-the-kubelet-cgroup-driver

kubeadm 支持在执行 `kubeadm init` 时，传递一个 `KubeletConfiguration` 结构体。 `KubeletConfiguration` 包含 `cgroupDriver` 字段，可用于控制 kubelet 的 cgroup 驱动。

这是一个最小化的cgroup使用systemd的配置示例，其中显式的配置了此字段：

```bash
# kubeadm-config.yaml
kind: ClusterConfiguration
apiVersion: kubeadm.k8s.io/v1beta3
kubernetesVersion: v1.21.0
---
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
cgroupDriver: systemd
```

### ~~1.6.1：命令行：#不推荐~~

```bash
#单master
# kubeadm  init  --apiserver-advertise-address=172.31.7.201  --apiserver-bind-port=6443  --kubernetes-version=v1.30.1  --pod-network-cidr=10.200.0.0/16 --service-cidr=10.100.0.0/16 --service-dns-domain=cluster.local --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers --ignore-preflight-errors=swap

#多master
# kubeadm  init  --apiserver-advertise-address=172.31.7.201  --control-plane-endpoint=172.31.7.188 --apiserver-bind-port=6443  --kubernetes-version=v1.30.1  --pod-network-cidr=10.200.0.0/16 --service-cidr=10.100.0.0/16 --service-dns-domain=cluster.local --image-repository=registry.cn-hangzhou.aliyuncs.com/google_containers --ignore-preflight-errors=swap
```

### 1.6.2：基于init文件初始化-推荐：

```bash
root@k8s-master1:~# kubeadm config print init-defaults #输出默认初始化配置
root@k8s-master1:~# kubeadm config print init-defaults > kubeadm-init.yaml #将默认配置输出至文件
root@k8s-master1:~# vim kubeadm-init.yaml #修改后的初始化文件内容
root@k8s-master1:~# cat kubeadm-init.yaml 
apiVersion: kubeadm.k8s.io/v1beta3
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: abcdef.0123456789abcdef
  ttl: 24h0m0s
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: 172.31.7.101
  bindPort: 6443
nodeRegistration:
  #criSocket: unix:///var/run/containerd/containerd.sock #k8S v1.24开始默认使用containerd
  criSocket: unix:///var/run/cri-dockerd.sock #如果k8S v1.24及新版本还要使用docker则需要使用cri-dockerd转发一次
  imagePullPolicy: IfNotPresent
  name: k8s-master1.example.com
  taints: null
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta3
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controlPlaneEndpoint: 172.31.7.188:6443 ##负载均衡VIP地址及端口,必须提前配置好
controllerManager: {}
dns: {}
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: registry.cn-hangzhou.aliyuncs.com/google_containers  #镜像仓库 
kind: ClusterConfiguration
kubernetesVersion: 1.30.1
networking:
networking:
  dnsDomain: cluster.local #service 域名后缀
  podSubnet: 10.200.0.0/16 #pod子网范围
  serviceSubnet: 10.100.0.0/16 #service子网范围
scheduler: {}


--- #指定kubelet使用systemd
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
cgroupDriver: systemd

--- #指定KubeProxy使用ipvs
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
```

### 1.6.3：执行初始化：

```bash
root@k8s-master1:~# kubeadm init --config kubeadm-init.yaml

Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

  mkdir -p $HOME/.kube
  sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
  sudo chown $(id -u):$(id -g) $HOME/.kube/config

Alternatively, if you are the root user, you can run:

  export KUBECONFIG=/etc/kubernetes/admin.conf

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
  https://kubernetes.io/docs/concepts/cluster-administration/addons/

You can now join any number of control-plane nodes by copying certificate authorities
and service account keys on each node and then running the following as root:

  kubeadm join 172.31.7.188:6443 --token abcdef.0123456789abcdef \
        --discovery-token-ca-cert-hash sha256:5d6123bbffea4230c2280b71a60ae36a220e65dc97ef6737bde13c50d4f58111 \
        --control-plane 

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 172.31.7.188:6443 --token abcdef.0123456789abcdef \
        --discovery-token-ca-cert-hash sha256:5d6123bbffea4230c2280b71a60ae36a220e65dc97ef6737bde13c50d4f58111
```

### 1.6.4：查看容器状态：

可以使用docker命令查看当前节点上运行的容器状态

![image-20240910160257209](images/image-20240910160257209.png)



## 1.7：添加节点：

添加node与master节点到当前K8S环境

### 1.7.1：添加node节点：

添加node节点指定使用cri-docker、如果不指定、默认使用的是containerd

```bash
root@k8s-node1:~# kubeadm join 172.31.7.188:6443 --token abcdef.0123456789abcdef --cri-socket unix:///var/run/cri-dockerd.sock \
        --discovery-token-ca-cert-hash sha256:5d6123bbffea4230c2280b71a60ae36a220e65dc97ef6737bde13c50d4f58111


root@k8s-node2:~# kubeadm join 172.31.7.188:6443 --token abcdef.0123456789abcdef --cri-socket unix:///var/run/cri-dockerd.sock \
        --discovery-token-ca-cert-hash sha256:5d6123bbffea4230c2280b71a60ae36a220e65dc97ef6737bde13c50d4f58111
        
root@k8s-node2:~# kubeadm join 172.31.7.188:6443 --token abcdef.0123456789abcdef --cri-socket unix:///var/run/cri-dockerd.sock \
        --discovery-token-ca-cert-hash sha256:5d6123bbffea4230c2280b71a60ae36a220e65dc97ef6737bde13c50d4f58111
```

### 1.7.2：添加master节点：

添加master并指定使用cri-dockerd，如果不指定默认使用的是containerd

```bash
#当前maste生成证书用于添加新控制节点：
root@k8s-master1:~# kubeadm  init phase upload-certs --upload-certs
W0910 16:05:05.780066    5687 version.go:104] could not fetch a Kubernetes version from the internet: unable to get URL "https://dl.k8s.io/release/stable-1.txt": Get "https://cdn.dl.k8s.io/release/stable-1.txt": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
W0910 16:05:05.780154    5687 version.go:105] falling back to the local client version: v1.30.1
[upload-certs] Storing the certificates in Secret "kubeadm-certs" in the "kube-system" Namespace
[upload-certs] Using certificate key:
23c70979fe4841ee05e7725ce22782b1d1210578ced5a6b5279f8af464d613be


#添加master2
root@k8s-master2:~# kubeadm join 172.31.7.188:6443 --token abcdef.0123456789abcdef --cri-socket unix:///var/run/cri-dockerd.sock \
        --discovery-token-ca-cert-hash sha256:5d6123bbffea4230c2280b71a60ae36a220e65dc97ef6737bde13c50d4f58111 \
        --control-plane --certificate-key  23c70979fe4841ee05e7725ce22782b1d1210578ced5a6b5279f8af464d613be
        

#添加master3
root@k8s-master3:~# kubeadm join 172.31.7.188:6443 --token abcdef.0123456789abcdef --cri-socket unix:///var/run/cri-dockerd.sock \
        --discovery-token-ca-cert-hash sha256:5d6123bbffea4230c2280b71a60ae36a220e65dc97ef6737bde13c50d4f58111 \
        --control-plane --certificate-key  23c70979fe4841ee05e7725ce22782b1d1210578ced5a6b5279f8af464d613be
```

### 1.7.3：验证节点：

目前网络组件还未部署，节点状态会显示为NotReady 

```bash
root@k8s-master1:~# kubectl get node
NAME                        STATUS     ROLES           AGE     VERSION
NAME                      STATUS     ROLES           AGE     VERSION
k8s-master1.example.com   NotReady   control-plane   5m58s   v1.30.1
k8s-master2.example.com   NotReady   control-plane   26s     v1.30.1
k8s-master3.example.com   NotReady   control-plane   7s      v1.30.1
k8s-node1.example.com     NotReady   <none>          112s    v1.30.1
k8s-node2.example.com     NotReady   <none>          114s    v1.30.1
k8s-node3.example.com     NotReady   <none>          117s    v1.30.1
```

### 1.7.4：查看集群leader信息：

查看kube-controller-manager与kube-scheduler的leader信息

```bash
root@k8s-master1:~# kubectl get leases -n kube-system
NAME                                   HOLDER                                                                      AGE
apiserver-dlnbhm5sbbuwjt5xaedlm2fzza   apiserver-dlnbhm5sbbuwjt5xaedlm2fzza_eb61ed4e-4c43-467c-bf10-064ed75db3ed   34s
apiserver-hitiscauk7soymvii3ujfifa5q   apiserver-hitiscauk7soymvii3ujfifa5q_b35516d9-822b-4836-847e-b18127418d48   6m22s
apiserver-lh7qshte2k5rxulkkzgtdydcaa   apiserver-lh7qshte2k5rxulkkzgtdydcaa_7ac9ac77-957c-4696-9209-95938307fc98   16s
kube-controller-manager                k8s-master1.example.com_7788db0c-c640-4cac-bab3-f44d9d79c5d5                6m20s
kube-scheduler                         k8s-master1.example.com_881440c7-f312-4da8-97ea-bd819cbaa072                6m18s
```

## 1.8：部署网络组件：

Flannel:  https://github.com/flannel-io/flannel



### 1.8.1：部署calico网络组件：

Calico: https://docs.tigera.io/calico/latest/getting-started/kubernetes/requirements

```bash
root@k8s-master1:~# kubectl apply -f calico_v3.28.1-k8s_1.29.8-ubuntu2404.yaml 
poddisruptionbudget.policy/calico-kube-controllers created
serviceaccount/calico-kube-controllers created
serviceaccount/calico-node created
serviceaccount/calico-cni-plugin created
configmap/calico-config created
customresourcedefinition.apiextensions.k8s.io/bgpconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/bgpfilters.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/bgppeers.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/blockaffinities.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/caliconodestatuses.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/clusterinformations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/felixconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/globalnetworkpolicies.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/globalnetworksets.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/hostendpoints.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamblocks.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamconfigs.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipamhandles.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ippools.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/ipreservations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/kubecontrollersconfigurations.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/networkpolicies.crd.projectcalico.org created
customresourcedefinition.apiextensions.k8s.io/networksets.crd.projectcalico.org created
clusterrole.rbac.authorization.k8s.io/calico-kube-controllers created
clusterrole.rbac.authorization.k8s.io/calico-node created
clusterrole.rbac.authorization.k8s.io/calico-cni-plugin created
clusterrolebinding.rbac.authorization.k8s.io/calico-kube-controllers created
clusterrolebinding.rbac.authorization.k8s.io/calico-node created
clusterrolebinding.rbac.authorization.k8s.io/calico-cni-plugin created
daemonset.apps/calico-node created
deployment.apps/calico-kube-controllers created
```

### 1.8.2：验证pod状态：

```bash
root@k8s-master1:~# kubectl  get  pod -n kube-system 
NAME                                              READY   STATUS    RESTARTS   AGE
calico-kube-controllers-5b7555dd59-6bxtk          1/1     Running   0          8m7s
calico-node-6vddc                                 1/1     Running   0          8m7s
calico-node-94tgg                                 1/1     Running   0          8m7s
calico-node-bkmqr                                 1/1     Running   0          8m7s
calico-node-bpd74                                 1/1     Running   0          8m7s
calico-node-h2lww                                 1/1     Running   0          8m7s
calico-node-lm8rx                                 1/1     Running   0          8m7s
coredns-7c445c467-ph88c                           1/1     Running   0          14m
coredns-7c445c467-qw44j                           1/1     Running   0          14m
etcd-k8s-master1.example.com                      1/1     Running   0          15m
etcd-k8s-master2.example.com                      1/1     Running   0          9m30s
etcd-k8s-master3.example.com                      1/1     Running   0          9m11s
kube-apiserver-k8s-master1.example.com            1/1     Running   0          15m
kube-apiserver-k8s-master2.example.com            1/1     Running   0          9m28s
kube-apiserver-k8s-master3.example.com            1/1     Running   0          9m9s
kube-controller-manager-k8s-master1.example.com   1/1     Running   0          15m
kube-controller-manager-k8s-master2.example.com   1/1     Running   0          9m28s
kube-controller-manager-k8s-master3.example.com   1/1     Running   0          9m11s
kube-proxy-5tfv6                                  1/1     Running   0          14m
kube-proxy-cchbz                                  1/1     Running   0          9m31s
kube-proxy-czn7v                                  1/1     Running   0          10m
kube-proxy-g9jlh                                  1/1     Running   0          11m
kube-proxy-hbgbq                                  1/1     Running   0          9m12s
kube-proxy-sfr54                                  1/1     Running   0          10m
kube-scheduler-k8s-master1.example.com            1/1     Running   0          15m
kube-scheduler-k8s-master2.example.com            1/1     Running   0          9m31s
kube-scheduler-k8s-master3.example.com            1/1     Running   0          9m9s
```

## 1.9：部署web服务并验证：

### 1.9.1：部署web服务：

```bash
root@k8s-master1:~# cd nginx-tomcat-case/
root@k8s-master1:~/nginx-tomcat-case# kubectl apply -f myserver-namespace.yaml 
namespace/myserver created

root@k8s-master1:~/nginx-tomcat-case# kubectl apply -f tomcat.yaml 
deployment.apps/myserver-tomcat-app1-deployment created
service/myserver-tomcat-app1-service created

root@k8s-master1:~/nginx-tomcat-case# kubectl apply -f nginx.yaml 
deployment.apps/myserver-nginx-deployment created
service/myserver-nginx-service created
```

### 1.9.2：验证pod状态：

```bash
root@k8s-master1:~/nginx-tomcat-case# kubectl get pod -n myserver
NAME                                               READY   STATUS    RESTARTS   AGE
myserver-nginx-deployment-5668cf768b-6p255         1/1     Running   0          60s
myserver-tomcat-app1-deployment-78bf755869-blgnz   1/1     Running   0          64s
root@k8s-master1:~/nginx-tomcat-case# 
root@k8s-master1:~/nginx-tomcat-case# kubectl get svc -n myserver
NAME                           TYPE       CLUSTER-IP       EXTERNAL-IP   PORT(S)                      AGE
myserver-nginx-service         NodePort   10.100.236.238   <none>        80:30004/TCP,443:30443/TCP   64s
myserver-tomcat-app1-service   NodePort   10.100.86.202    <none>        80:30005/TCP                 68s
```

### 1.9.3：验证服务访问：

![image-20240910123135166](images/image-20240910123135166.png)

## 1.10：部署官方dashboard：

可选组件、非必须

https://github.com/kubernetes/dashboard

### 1.10.1：执行部署：

```bash
root@k8s-master1:~# cd dashboard-v2.7.0/
root@k8s-master1:~/dashboard-v2.7.0# kubectl apply -f dashboard-v2.7.0.yaml -f admin-user.yaml  -f admin-secret.yaml
namespace/kubernetes-dashboard created
serviceaccount/kubernetes-dashboard created
service/kubernetes-dashboard created
secret/kubernetes-dashboard-certs created
secret/kubernetes-dashboard-csrf created
secret/kubernetes-dashboard-key-holder created
configmap/kubernetes-dashboard-settings created
role.rbac.authorization.k8s.io/kubernetes-dashboard created
clusterrole.rbac.authorization.k8s.io/kubernetes-dashboard created
rolebinding.rbac.authorization.k8s.io/kubernetes-dashboard created
clusterrolebinding.rbac.authorization.k8s.io/kubernetes-dashboard created
deployment.apps/kubernetes-dashboard created
service/dashboard-metrics-scraper created
deployment.apps/dashboard-metrics-scraper created
serviceaccount/admin-user created
clusterrolebinding.rbac.authorization.k8s.io/admin-user created
secret/dashboard-admin-user created

root@k8s-master1:~/dashboard-v2.7.0# kubectl  apply -f metrics-server-v0.7.1.yaml #获取指标数据
serviceaccount/metrics-server created
clusterrole.rbac.authorization.k8s.io/system:aggregated-metrics-reader created
clusterrole.rbac.authorization.k8s.io/system:metrics-server created
rolebinding.rbac.authorization.k8s.io/metrics-server-auth-reader created
clusterrolebinding.rbac.authorization.k8s.io/metrics-server:system:auth-delegator created
clusterrolebinding.rbac.authorization.k8s.io/system:metrics-server created
service/metrics-server created
deployment.apps/metrics-server created
apiservice.apiregistration.k8s.io/v1beta1.metrics.k8s.io created
```

### 1.10.2：验证pod状态：

```bash
root@k8s-master1:~/dashboard-v2.7.0# kubectl get pod -n kubernetes-dashboard
NAME                                         READY   STATUS    RESTARTS   AGE
dashboard-metrics-scraper-77d58f5579-bqrm2   1/1     Running   0          23s
kubernetes-dashboard-56d5d4fdd9-7krmr        1/1     Running   0          23s
```

### 1.10.3：获取token：

```bash
root@k8s-master1:~# kubectl get secret -A | grep admin
kubernetes-dashboard   dashboard-admin-user              kubernetes.io/service-account-token   3      109s

root@k8s-master1:~# kubectl  describe secret -n kubernetes-dashboard   dashboard-admin-user
Name:         dashboard-admin-user
Namespace:    kubernetes-dashboard
Labels:       <none>
Annotations:  kubernetes.io/service-account.name: admin-user
              kubernetes.io/service-account.uid: 17876304-89b5-44d1-8b4d-d73d2168c741

Type:  kubernetes.io/service-account-token

Data
====
ca.crt:     1107 bytes
namespace:  20 bytes
token:      eyJhbGciOiJSUzI1NiIsImtpZCI6ImNfTDRhbk1LcnR0RkpmcFItN0lRMkp1elk5bHpfRElGWWtScFBJQy1UVncifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlcm5ldGVzLWRhc2hib2FyZCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJkYXNoYm9hcmQtYWRtaW4tdXNlciIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJhZG1pbi11c2VyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQudWlkIjoiMTc4NzYzMDQtODliNS00NGQxLThiNGQtZDczZDIxNjhjNzQxIiwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmVybmV0ZXMtZGFzaGJvYXJkOmFkbWluLXVzZXIifQ.FDXUXZ_q0f9AZ1p599B8jv5igz_lTVONDgnQBnu8srDwQuDu-yzxmOMZyO0R2hq5OdV49Swkt9kfDk2vzhrchsfK84S8_m6c3cuPOXrlrsNd2P65Dw_f2lqnzYVRknsuHgxXzjIyhwiWJOvngYqKw-kqE63pjh6kIopBYdEtmuWkTBSABYX6UV-pI9obOz5MYaA-M7xaO3Z-LUksqVbw-TxF2_hh30DXMb9KohYpsfbykCYnz8KvsDaEZx6gwYcwe90Bejy4tJ7NmS0PGcxEfY40IIuDxyPTTTOG26A62tAXehT5rLDw7jmQINMyrHJBA_pcDwndgyCdHMZE_Q5zhw
```

### 1.10.4：浏览器登录dashboard：

浏览器使用https访问任意一个node节点IP+30000端口，端口可以在部署的 yaml文件中自定义修改

![image-20240910124141528](images/image-20240910124141528.png)



![image-20240910124157286](images/image-20240910124157286.png)



![image-20240910124211996](images/image-20240910124211996.png)



![image-20240910124238593](images/image-20240910124238593.png)

#以下CPU和内存使用图形需要部署了metrics-server组件才会显示:

![image-20240910163141088](images/image-20240910163141088.png)



![image-20240910162211596](images/image-20240910162211596.png)



