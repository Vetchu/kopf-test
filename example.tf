
resource "nsxt_policy_gateway_policy" "gateway_policy" {
  display_name    = "${var.env_name}-gateway-policy"
  category        = "LocalGatewayRules"
  locked          = false
  sequence_number = 1
  stateful        = true
  tcp_strict      = false

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }

  dynamic "rule" {
    for_each = local.standard_ports ? [""] : []
    content {
      display_name       = "allow-standard-ports"
      action             = "ALLOW"
      direction          = "IN_OUT"
      ip_version         = "IPV4_IPV6"
      services           = [nsxt_policy_service.standard_ports_service[0].path]
      destination_groups = ["${var.k8s_lb_public_ip}"]
      scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
    }
  }

  rule {
    display_name  = "allow-all-internal"
    action        = "ALLOW"
    direction     = "IN_OUT"
    ip_version    = "IPV4_IPV6"
    source_groups = ["${var.network_cidr}"]
    scope         = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-ssh"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    destination_groups = ["${var.jumpbox_public_ip}", "${var.dns_instance_public_ip}"]
    services           = [nsxt_policy_service.ssh_port_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  dynamic "rule" {
    for_each = local.ports_3190_3199 ? [""] : []
    content {
      display_name       = "allow-ports-3190-3199"
      action             = "ALLOW"
      direction          = "IN_OUT"
      ip_version         = "IPV4_IPV6"
      services           = [nsxt_policy_service.ports_3190_3199_service[0].path]
      source_groups      = ["10.74.85.2/32"]
      destination_groups = ["${var.k8s_lb_public_ip}"]
      scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
    }
  }

  dynamic "rule" {
    for_each = local.ports_3290_3299 ? [""] : []
    content {
      display_name       = "allow-ports-3290-3299"
      action             = "ALLOW"
      direction          = "IN_OUT"
      ip_version         = "IPV4_IPV6"
      services           = [nsxt_policy_service.ports_3290_3299_service[0].path]
      source_groups      = ["10.74.85.2/32"]
      destination_groups = ["${var.k8s_lb_public_ip}"]
      scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
    }
  }

  rule {
    display_name       = "allow-3101"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.74.85.2/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3101_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3115"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.74.85.2/32", "10.113.97.251/32", "131.237.94.132/32", "10.113.99.139/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3115_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3116"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.31.45.109/32", "145.45.13.166/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3116_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3117"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.113.97.251/32", "10.113.99.139/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3117_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3118"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.31.45.109/32", "145.45.13.166/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3118_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3119"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.113.97.251/32", "10.113.99.139/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3119_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3201"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.74.85.2/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3201_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3208"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.113.97.251/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3208_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3215"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.74.85.2/32", "10.113.97.251/32", "10.48.106.250/32", "131.237.94.132/32", "10.113.99.139/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3215_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3216"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.31.45.109/32", "145.45.13.166/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3216_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3217"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.113.97.251/32", "10.113.99.139/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3217_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3278"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.55.7.192/26"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3278_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3315"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.113.99.139/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3315_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3317"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.113.99.139/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3317_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-12200-12201"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.55.53.0/24", "10.55.54.0/24"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_12200_service.path, nsxt_policy_service.port_12201_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

  rule {
    display_name       = "allow-3408"
    action             = "ALLOW"
    direction          = "IN_OUT"
    ip_version         = "IPV4_IPV6"
    source_groups      = ["10.124.20.2/32"]
    destination_groups = ["${var.k8s_lb_public_ip}"]
    services           = [nsxt_policy_service.port_3408_service.path]
    scope              = [data.nsxt_policy_tier1_gateway.k8s_tier1_router.path]
  }

}

locals {
  standard_ports_tcp  = ["80", "443", "6443"]
  standard_ports_udp  = []
  ports_3190_3199_tcp = ["3190-3199"]
  ports_3206_3207_tcp = ["3206-3207"]
  ports_3290_3299_tcp = ["3290-3299"]

  standard_ports      = (length(local.standard_ports_tcp) > 0 || length(local.standard_ports_udp) > 0)
  ports_3190_3199     = (length(local.ports_3190_3199_tcp) > 0)
  ports_3206_3207     = (length(local.ports_3206_3207_tcp) > 0)
  ports_3290_3299     = (length(local.ports_3290_3299_tcp) > 0)
}

resource "nsxt_policy_service" "standard_ports_service" {
  count        = local.standard_ports ? 1 : 0
  display_name = "standard-ports-service"

  dynamic "l4_port_set_entry" {
    for_each = { for key, value in { TCP = local.standard_ports_tcp, UDP = local.standard_ports_udp } : key => value if length(value) > 0 }
    content {
      display_name      = "standard-ports"
      destination_ports = l4_port_set_entry.value
      protocol          = l4_port_set_entry.key
    }
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}


resource "nsxt_policy_service" "ports_3190_3199_service" {
  count        = local.ports_3190_3199 ? 1 : 0
  display_name = "ports-3190_3199-service"

  dynamic "l4_port_set_entry" {
    for_each = { for key, value in { TCP = local.ports_3190_3199_tcp } : key => value if length(value) > 0 }
    content {
      display_name      = "ports_3190_3199"
      destination_ports = l4_port_set_entry.value
      protocol          = l4_port_set_entry.key
    }
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "ports_3206_3207_service" {
  count        = local.ports_3206_3207 ? 1 : 0
  display_name = "ports-3206_3207-service"

  dynamic "l4_port_set_entry" {
    for_each = { for key, value in { TCP = local.ports_3206_3207_tcp } : key => value if length(value) > 0 }
    content {
      display_name      = "ports_3206_3207"
      destination_ports = l4_port_set_entry.value
      protocol          = l4_port_set_entry.key
    }
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "ports_3290_3299_service" {
  count        = local.ports_3290_3299 ? 1 : 0
  display_name = "ports-3290_3299-service"

  dynamic "l4_port_set_entry" {
    for_each = { for key, value in { TCP = local.ports_3290_3299_tcp } : key => value if length(value) > 0 }
    content {
      display_name      = "ports_3290_3299"
      destination_ports = l4_port_set_entry.value
      protocol          = l4_port_set_entry.key
    }
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3115_service" {
  display_name = "3115-port-service"
  l4_port_set_entry {
    display_name      = "3115-port"
    protocol          = "TCP"
    destination_ports = ["3115"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3116_service" {
  display_name = "3116-port-service"
  l4_port_set_entry {
    display_name      = "3116-port"
    protocol          = "TCP"
    destination_ports = ["3116"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3117_service" {
  display_name = "3117-port-service"
  l4_port_set_entry {
    display_name      = "3117-port"
    protocol          = "TCP"
    destination_ports = ["3117"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3118_service" {
  display_name = "3118-port-service"
  l4_port_set_entry {
    display_name      = "3118-port"
    protocol          = "TCP"
    destination_ports = ["3118"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3119_service" {
  display_name = "3119-port-service"
  l4_port_set_entry {
    display_name      = "3119-port"
    protocol          = "TCP"
    destination_ports = ["3119"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3201_service" {
  display_name = "3201-port-service"
  l4_port_set_entry {
    display_name      = "3201-port"
    protocol          = "TCP"
    destination_ports = ["3201"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3215_service" {
  display_name = "3215-port-service"
  l4_port_set_entry {
    display_name      = "3215-port"
    protocol          = "TCP"
    destination_ports = ["3215"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3216_service" {
  display_name = "3216-port-service"
  l4_port_set_entry {
    display_name      = "3216-port"
    protocol          = "TCP"
    destination_ports = ["3216"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3217_service" {
  display_name = "3217-port-service"
  l4_port_set_entry {
    display_name      = "3217-port"
    protocol          = "TCP"
    destination_ports = ["3217"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3278_service" {
  display_name = "3278-port-service"
  l4_port_set_entry {
    display_name      = "3278-port"
    protocol          = "TCP"
    destination_ports = ["3278"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3315_service" {
  display_name = "3315-port-service"
  l4_port_set_entry {
    display_name      = "3315-port"
    protocol          = "TCP"
    destination_ports = ["3315"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3317_service" {
  display_name = "3317-port-service"
  l4_port_set_entry {
    display_name      = "3317-port"
    protocol          = "TCP"
    destination_ports = ["3317"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3208_service" {
  display_name = "3208-port-service"
  l4_port_set_entry {
    display_name      = "3208-port"
    protocol          = "TCP"
    destination_ports = ["3208"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_12200_service" {
  display_name = "12200-port-service"
  l4_port_set_entry {
    display_name      = "12200-port"
    protocol          = "TCP"
    destination_ports = ["12200"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_12201_service" {
  display_name = "12201-port-service"
  l4_port_set_entry {
    display_name      = "12201-port"
    protocol          = "TCP"
    destination_ports = ["12201"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

resource "nsxt_policy_service" "port_3408_service" {
  display_name = "3408-port-service"
  l4_port_set_entry {
    display_name      = "3408-port"
    protocol          = "TCP"
    destination_ports = ["3408"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}


resource "nsxt_policy_service" "ssh_port_service" {
  display_name = "ssh-port-service"
  l4_port_set_entry {
    display_name      = "ssh-port"
    protocol          = "TCP"
    destination_ports = ["22"]
  }

  tag {
    scope = var.env_name
    tag   = "gateway_policy"
  }
}

####    Tier 1 Gateway

data "nsxt_policy_tier1_gateway" "k8s_tier1_router" {
  display_name = "${var.env_name}-dmz"
}
