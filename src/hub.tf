terraform {
    backend "local" {
    }
}

provider "azurerm" {
  alias  = "production"

  features {}

  subscription_id = var.subscription_production

  version = "~>2.18.0"
}

provider "azurerm" {
    #alias = "target"

    features {}

    subscription_id = var.environment == "production" ? var.subscription_production : var.subscription_test

    version = "~>2.18.0"
}


#
# LOCALS
#

locals {
  location_map = {
    australiacentral = "auc",
    australiacentral2 = "auc2",
    australiaeast = "aue",
    australiasoutheast = "ause",
    brazilsouth = "brs",
    canadacentral = "cac",
    canadaeast = "cae",
    centralindia = "inc",
    centralus = "usc",
    eastasia = "ase",
    eastus = "use",
    eastus2 = "use2",
    francecentral = "frc",
    francesouth = "frs",
    germanynorth = "den",
    germanywestcentral = "dewc",
    japaneast = "jpe",
    japanwest = "jpw",
    koreacentral = "krc",
    koreasouth = "kre",
    northcentralus = "usnc",
    northeurope = "eun",
    norwayeast = "noe",
    norwaywest = "now",
    southafricanorth = "zan",
    southafricawest = "zaw",
    southcentralus = "ussc",
    southeastasia = "asse",
    southindia = "ins",
    switzerlandnorth = "chn",
    switzerlandwest = "chw",
    uaecentral = "aec",
    uaenorth = "aen",
    uksouth = "uks",
    ukwest = "ukw",
    westcentralus = "uswc",
    westeurope = "euw",
    westindia = "inw",
    westus = "usw",
    westus2 = "usw2",
  }
}

locals {
  environment_short = substr(var.environment, 0, 1)
  location_short = lookup(local.location_map, var.location, "aue")
}

# Name prefixes
locals {
  name_prefix = "${local.environment_short}-${local.location_short}"
  name_prefix_tf = "${local.name_prefix}-tf-${var.category}"
}

locals {
  common_tags = {
    category    = "${var.category}"
    environment = "${var.environment}"
    location    = "${var.location}"
    source      = "${var.meta_source}"
    version     = "${var.meta_version}"
  }

  extra_tags = {
  }
}

# Network security rules
locals {
  default_nsg_rule = {
    direction                                  = "Inbound"
    access                                     = "Allow"
    protocol                                   = "Tcp"
    description                                = null
    source_port_range                          = null
    source_port_ranges                         = null
    destination_port_range                     = null
    destination_port_ranges                    = null
    source_address_prefix                      = null
    source_address_prefixes                    = null
    source_application_security_group_ids      = null
    destination_address_prefix                 = null
    destination_address_prefixes               = null
    destination_application_security_group_ids = null
  }
  default_mgmt_nsg_rules = [
    {
      name                       = "allow-load-balancer"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "AzureLoadBalancer"
      destination_address_prefix = "*"
    },
    {
      name                       = "deny-other"
      access                     = "Deny"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "VirtualNetwork"
      destination_address_prefix = "VirtualNetwork"
    }
  ]

  merged_mgmt_nsg_rules = flatten([
    for nsg in var.management_nsg_rules : merge(local.default_nsg_rule, nsg)
  ])

  merged_dmz_nsg_rules = flatten([
    for nsg in var.dmz_nsg_rules : merge(local.default_nsg_rule, nsg)
  ])
}

# Diagnostics
locals {
  diag_vnet_logs = [
    "VMProtectionAlerts",
  ]
  diag_vnet_metrics = [
    "AllMetrics",
  ]
  diag_nsg_logs = [
    "NetworkSecurityGroupEvent",
    "NetworkSecurityGroupRuleCounter",
  ]
  diag_pip_logs = [
    "DDoSProtectionNotifications",
    "DDoSMitigationFlowLogs",
    "DDoSMitigationReports",
  ]
  diag_pip_metrics = [
    "AllMetrics",
  ]
  diag_fw_logs = [
    "AzureFirewallApplicationRule",
    "AzureFirewallNetworkRule",
  ]
  diag_fw_metrics = [
    "AllMetrics",
  ]

  diag_all_logs = setunion(
    local.diag_vnet_logs,
    local.diag_nsg_logs,
    local.diag_pip_logs,
  local.diag_fw_logs)
  diag_all_metrics = setunion(
    local.diag_vnet_metrics,
    local.diag_pip_metrics,
  local.diag_fw_metrics)

  parsed_diag = {
    log_analytics_id   = "e1c46677-b6e1-4c5a-8983-bfecd30e5061"
    metric             = local.diag_all_metrics
    log                = local.diag_all_logs
    }
}

data "azurerm_client_config" "current" {}

data "azurerm_log_analytics_workspace" "log_analytics_workspace" {
  name                = "p-aue-tf-analytics-law-logs"
  provider = azurerm.production
  resource_group_name = "p-aue-tf-analytics-rg"
}

locals {
  network_watcher_name = "NetworkWatcher_${local.location_short}"
  network_watcher_resource_group = "NetworkWatcherRG"
}

#
# Resource group
#

resource "azurerm_resource_group" "rg" {
  location = var.location
  name = "${local.name_prefix_tf}-rg"

  tags = merge( local.common_tags, local.extra_tags, var.tags )
}

#
# Key vault
#

resource "azurerm_key_vault" "keys" {
  enabled_for_deployment      = true
  enabled_for_disk_encryption = true
  location                    = var.location
  name                        = "${local.name_prefix_tf}-kv"
  purge_protection_enabled    = false
  resource_group_name         = azurerm_resource_group.rg.name
  sku_name = "standard"
  soft_delete_enabled         = false
  tenant_id                   = data.azurerm_client_config.current.tenant_id

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "get",
    ]

    secret_permissions = [
      "get",
    ]

    storage_permissions = [
      "get",
    ]
  }

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  tags = merge( local.common_tags, local.extra_tags, var.tags )
}

#
# Storage account for flow logs
#

resource "azurerm_storage_account" "storage" {
  access_tier               = "Hot"
  account_kind              = "StorageV2"
  account_replication_type  = "LRS"
  account_tier              = "Standard"
  enable_https_traffic_only = true
  location                  = var.location
  name                      = lower(replace("${local.name_prefix_tf}st", "/[[:^alnum:]]/", ""))
  resource_group_name       = azurerm_resource_group.rg.name
  tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_advanced_threat_protection" "threat_protection" {
  enabled            = true
  target_resource_id = azurerm_storage_account.storage.id
}

#
# Hub network with subnets
#

resource "azurerm_virtual_network" "vnet" {
  address_space = [var.address_space]
  location = var.location
  name = "${local.name_prefix_tf}-vn"
  resource_group_name = azurerm_resource_group.rg.name

  tags = merge( local.common_tags, local.extra_tags, var.tags )
}

# Set the user principals who are allowed to peer vnets
resource "azurerm_role_assignment" "peering" {
  count = length(var.peering_assignment)
  principal_id = var.peering_assignment[count.index]
  role_definition_name = "Network Contributor"
  scope = azurerm_virtual_network.vnet.id
}

resource "azurerm_monitor_diagnostic_setting" "vnet" {
  count                          = 1
  name                           = "${local.name_prefix_tf}-mds-vnet"
  target_resource_id             = azurerm_virtual_network.vnet.id
  log_analytics_workspace_id     = data.azurerm_log_analytics_workspace.log_analytics_workspace.id

  dynamic "log" {
    for_each = setintersection(local.parsed_diag.log, local.diag_vnet_logs)
    content {
      category = log.value

      retention_policy {
        enabled = false
      }
    }
  }

  dynamic "metric" {
    for_each = setintersection(local.parsed_diag.metric, local.diag_vnet_metrics)
    content {
      category = metric.value

      retention_policy {
        enabled = false
      }
    }
  }
}

#
# Firewall subnet
#

resource "azurerm_subnet" "firewall" {
  address_prefixes = [ cidrsubnet(var.address_space, 2, 0) ]
  name = "AzureFirewallSubnet" # Must be named like this
  resource_group_name = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
}

#
# Gateway subnet
#

resource "azurerm_subnet" "gateway" {
  address_prefixes = [ cidrsubnet(var.address_space, 2, 1) ]
  name = "GatewaySubnet" # Must be named like this
  resource_group_name = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name

  service_endpoints = [
    "Microsoft.Storage",
  ]
}

#
# Management subnet
#

resource "azurerm_subnet" "mgmt" {
  address_prefixes = [ cidrsubnet(var.address_space, 2, 2) ]
  name = "${local.name_prefix_tf}-sn-management"
  resource_group_name = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name

  service_endpoints = [
    "Microsoft.Storage",
  ]
}

#
# DMZ subnet
#

resource "azurerm_subnet" "dmz" {
  address_prefixes = [ cidrsubnet(var.address_space, 2, 3) ]
  name = "${local.name_prefix_tf}-sn-dmz"
  resource_group_name = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name

  service_endpoints = [
    "Microsoft.Storage",
  ]
}

#
# Route table
#

resource "azurerm_route_table" "out" {
  name = "${local.name_prefix_tf}-rt-outbound"
  location = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_subnet_route_table_association" "mgmt" {
  route_table_id = azurerm_route_table.out.id
  subnet_id = azurerm_subnet.mgmt.id
}

resource "azurerm_subnet_route_table_association" "dmz" {
  route_table_id = azurerm_route_table.out.id
  subnet_id = azurerm_subnet.dmz.id
}

#
# Network security groups
#

# Management subnet
resource "azurerm_network_security_group" "mgmt" {
  location = azurerm_resource_group.rg.location
  name = "${local.name_prefix_tf}-nsg-mgmt"
  resource_group_name = azurerm_resource_group.rg.name

  tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_network_watcher_flow_log" "mgmt" {
  enabled = true
  network_security_group_id = azurerm_network_security_group.mgmt.id
  network_watcher_name = local.network_watcher_name
  provider = azurerm.production
  resource_group_name = local.network_watcher_resource_group
  storage_account_id = azurerm_storage_account.storage.id

  retention_policy {
    enabled = true
    days    = 7
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = data.azurerm_log_analytics_workspace.log_analytics_workspace.workspace_id
    workspace_region      = var.location
    workspace_resource_id = data.azurerm_log_analytics_workspace.log_analytics_workspace.id
    interval_in_minutes   = 10
  }
}

resource "azurerm_network_security_rule" "mgmt" {
  access = local.merged_mgmt_nsg_rules[count.index].access
  count = length(local.merged_mgmt_nsg_rules)

  description = local.merged_mgmt_nsg_rules[count.index].description

  destination_address_prefix = local.merged_mgmt_nsg_rules[count.index].destination_address_prefix
  destination_address_prefixes = local.merged_mgmt_nsg_rules[count.index].destination_address_prefixes
  destination_application_security_group_ids = local.merged_mgmt_nsg_rules[count.index].destination_application_security_group_ids
  destination_port_range = local.merged_mgmt_nsg_rules[count.index].destination_port_range
  destination_port_ranges = local.merged_mgmt_nsg_rules[count.index].destination_port_ranges

  direction = local.merged_mgmt_nsg_rules[count.index].direction
  name = local.merged_mgmt_nsg_rules[count.index].name
  network_security_group_name = azurerm_network_security_group.mgmt.name
  priority = 100 + 100 * count.index
  protocol = local.merged_mgmt_nsg_rules[count.index].protocol
  resource_group_name = azurerm_resource_group.rg.name

  source_address_prefix = local.merged_mgmt_nsg_rules[count.index].source_address_prefix
  source_address_prefixes = local.merged_mgmt_nsg_rules[count.index].source_address_prefixes
  source_application_security_group_ids = local.merged_mgmt_nsg_rules[count.index].source_application_security_group_ids
  source_port_range = local.merged_mgmt_nsg_rules[count.index].source_port_range
  source_port_ranges = local.merged_mgmt_nsg_rules[count.index].source_port_ranges
}

resource "azurerm_monitor_diagnostic_setting" "mgmt" {
  count                          = 1
  log_analytics_workspace_id     = data.azurerm_log_analytics_workspace.log_analytics_workspace.id
  name                           = "${local.name_prefix_tf}-mds-nsg-mgnt"
  target_resource_id             = azurerm_network_security_group.mgmt.id

  dynamic "log" {
    for_each = setintersection(local.parsed_diag.log, local.diag_nsg_logs)
    content {
      category = log.value

      retention_policy {
        enabled = false
      }
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "mgmt" {
  network_security_group_id = azurerm_network_security_group.mgmt.id
  subnet_id = azurerm_subnet.mgmt.id
}

# DMZ subnet
resource "azurerm_network_security_group" "dmz" {
  location = azurerm_resource_group.rg.location
  name = "${local.name_prefix_tf}-nsg-dmz"
  resource_group_name = azurerm_resource_group.rg.name

  tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_network_watcher_flow_log" "dmz" {
  enabled                   = true
  network_security_group_id = azurerm_network_security_group.dmz.id
  network_watcher_name = local.network_watcher_name
  provider = azurerm.production
  resource_group_name = local.network_watcher_resource_group
  storage_account_id        = azurerm_storage_account.storage.id

  retention_policy {
    enabled = true
    days    = 7
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = data.azurerm_log_analytics_workspace.log_analytics_workspace.workspace_id
    workspace_region      = var.location
    workspace_resource_id = data.azurerm_log_analytics_workspace.log_analytics_workspace.id
    interval_in_minutes   = 10
  }
}

resource "azurerm_network_security_rule" "dmz" {
  access = local.merged_dmz_nsg_rules[count.index].access
  count = length(local.merged_dmz_nsg_rules)
  description = local.merged_dmz_nsg_rules[count.index].description

  destination_address_prefix = local.merged_dmz_nsg_rules[count.index].destination_address_prefix
  destination_address_prefixes = local.merged_dmz_nsg_rules[count.index].destination_address_prefixes
  destination_application_security_group_ids = local.merged_dmz_nsg_rules[count.index].destination_application_security_group_ids
  destination_port_range = local.merged_dmz_nsg_rules[count.index].destination_port_range
  destination_port_ranges = local.merged_dmz_nsg_rules[count.index].destination_port_ranges

  direction = local.merged_dmz_nsg_rules[count.index].direction
  name = local.merged_dmz_nsg_rules[count.index].name
  network_security_group_name = azurerm_network_security_group.dmz.name
  priority = 100 + 100 * count.index
  protocol = local.merged_dmz_nsg_rules[count.index].protocol
  resource_group_name = azurerm_resource_group.rg.name

  source_address_prefix = local.merged_dmz_nsg_rules[count.index].source_address_prefix
  source_address_prefixes = local.merged_dmz_nsg_rules[count.index].source_address_prefixes
  source_application_security_group_ids = local.merged_dmz_nsg_rules[count.index].source_application_security_group_ids
  source_port_range = local.merged_dmz_nsg_rules[count.index].source_port_range
  source_port_ranges = local.merged_dmz_nsg_rules[count.index].source_port_ranges
}

resource "azurerm_monitor_diagnostic_setting" "dmz" {
  count                          = 1
  log_analytics_workspace_id     = data.azurerm_log_analytics_workspace.log_analytics_workspace.id
  name                           = "${local.name_prefix_tf}-mds-nsg-dmz"
  target_resource_id             = azurerm_network_security_group.dmz.id

  dynamic "log" {
    for_each = setintersection(local.parsed_diag.log, local.diag_nsg_logs)
    content {
      category = log.value

      retention_policy {
        enabled = false
      }
    }
  }
}

resource "azurerm_subnet_network_security_group_association" "dmz" {
  network_security_group_id = azurerm_network_security_group.dmz.id
  subnet_id = azurerm_subnet.dmz.id
}

#
# Private DNS
#

resource "azurerm_private_dns_zone" "main" {
  count = var.private_dns_zone != null ? 1 : 0
  name = var.private_dns_zone
  resource_group_name = azurerm_resource_group.rg.name

  tags = merge( local.common_tags, local.extra_tags, var.tags )
}

resource "azurerm_private_dns_zone_virtual_network_link" "main" {
  count = var.private_dns_zone != null ? 1 : 0
  name = "${local.name_prefix_tf}-dnsl-main"
  private_dns_zone_name = azurerm_private_dns_zone.main[0].name
  registration_enabled = true
  resource_group_name = azurerm_resource_group.rg.name
  tags = merge( local.common_tags, local.extra_tags, var.tags )
  virtual_network_id = azurerm_virtual_network.vnet.id
}

resource "azurerm_role_assignment" "dns" {
  count = var.private_dns_zone != null ? length(var.peering_assignment) : 0
  principal_id = var.peering_assignment[count.index]
  role_definition_name = "Private DNS Zone Contributor"
  scope = azurerm_private_dns_zone.main[0].id
}
