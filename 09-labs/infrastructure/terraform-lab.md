# Lab Estate with Terraform

| Field | Value |
|---|---|
| `estate_id` | LAB-ESTATE-01 |
| `provider` | docker (default), libvirt (hypervisor) |
| `isolation` | internal bridge network, no default route |

## 1. Minimal estate

```hcl
terraform {
  required_version = ">= 1.6"
  required_providers {
    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }
  }
}

provider "docker" {}

variable "lab_subnet" { default = "172.28.0.0/24" }

resource "docker_network" "lab" {
  name = "ssa-lab"
  # internal = true -> no external connectivity
  internal = true
  ipam_config {
    subnet = var.lab_subnet
  }
}

resource "docker_image" "target" {
  name = "vulnerables/web-dvwa:latest"
}

resource "docker_container" "target" {
  name  = "ssa-target"
  image = docker_image.target.image_id
  networks_advanced { name = docker_network.lab.name }
  ports {
    internal = 8080
    external = 0            # never publish to the host
  }
  labels = {
    ssa_role   = "web-target"
    ssa_lab    = "LAB-ESTATE-01"
    ssa_owner  = "lab-maintainer"
  }
}

resource "docker_image" "attacker" {
  name = "kalilinux/kali-rolling:latest"
}

resource "docker_container" "attacker" {
  name      = "ssa-attacker"
  image     = docker_image.attacker.image_id
  networks_advanced { name = docker_network.lab.name }
  tty = true
  stdin_open = true
  privileged = false         # privilege would invalidate the exercise
}

output "lab_network" { value = docker_network.lab.name }
```

## 2. Host firewall for the lab segment

```bash
# Linux host acting as the lab router
sudo iptables -A FORWARD -s 172.28.0.0/24 -d 0.0.0.0/0 -j DROP
sudo iptables -A FORWARD -s 172.28.0.0/24 -d 172.28.0.0/24 -j ACCEPT
sudo ip route add blackhole 0.0.0.0/1 dev lo
```

Windows equivalent (for PowerShell lab hosts):

```powershell
New-NetFirewallRule -DisplayName "SSA lab egress deny" -Direction Outbound `
  -RemoteAddress Internet -InterfaceAlias "vEthernet (ssa-lab)" -Action Block
```

## 3. Expected telemetry per estate

| Lab asset | Sensor | Expected |
|---|---|---|
| `ssa-target` | Suricata (host network mode) | sids from `06-defense/suricata/rules/` |
| `ssa-target` | Wazuh agent | rules 100010-100099, 101000-101099 |
| all containers | Docker daemon events | privileged / host-mount flags |
| lab host | OS audit | `auditd execve` for 101000-101004 |

## 4. Reset procedure

```bash
terraform destroy -auto-approve
docker network prune -f
# never: docker system prune -a --volumes  (destroys unrelated work)
```
