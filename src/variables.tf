#
# ENVIRONMENT
#

variable "category" {
    default = "nwk-hub"
    description = "The name of the category that all the resources are running in."
}

variable "environment" {
    default = "production"
    description = "The name of the environment that all the resources are running in."
}

#
# LOCATION
#

variable "location" {
    default = "australiaeast"
    description = "The full name of the Azure region in which the resources should be created."
}

#
# META
#

variable "meta_source" {
    description = "The commit ID of the current commit from which the plan is being created."
    type = string
}

variable "meta_version" {
    description = "The version of the infrastructure as it is being generated."
    type = string
}

#
# NETWORK
#

variable "address_space" {
    default = "10.1.1.0/24"
    description = "The full address space that is used the virtual network. Requires at least a /24 address space."
}

#
# NETWORK - DDOS
#

variable "create_ddos_plan" {
  description = "Create a DDos protection plan and attach to vnet."
  type = bool
  default = false
}

#
# NETWORK - DNS
#

variable "private_dns_zone" {
  description = "Name of private dns zone to create and associate with virtual network."
  default = "hub.azure.calvinverse.net"
}

#
# NETWORK - FIREWALL
#

variable "firewall_zones" {
  default = null
  description = "A collection of availability zones to spread the Firewall over."
  type = list(string)
}

variable "firewall_application_rules" {
  default = []
  description = "List of application rules to apply to firewall."
  type = list(object({ name = string, action = string, source_addresses = list(string), target_fqdns = list(string), protocol = object({ type = string, port = string }) }))
}

variable "firewall_network_rules" {
  default = []
  description = "List of network rules to apply to firewall."
  type = list(object({ name = string, action = string, source_addresses = list(string), destination_ports = list(string), destination_addresses = list(string), protocols = list(string) }))
}

variable "firewall_nat_rules" {
  default = []
  description = "List of nat rules to apply to firewall."
  type = list(object({ name = string, action = string, source_addresses = list(string), destination_ports = list(string), destination_addresses = list(string), protocols = list(string), translated_address = string, translated_port = string }))
}

variable "service_endpoints" {
  description = "Service endpoints to add to the firewall subnet."
  type        = list(string)
  default = [
    "Microsoft.AzureActiveDirectory",
    "Microsoft.AzureCosmosDB",
    "Microsoft.EventHub",
    "Microsoft.KeyVault",
    "Microsoft.ServiceBus",
    "Microsoft.Sql",
    "Microsoft.Storage",
  ]
}

#
# NETWORK - PUBLIC IP
#

variable "public_ip_name" {
  default = "fw-public"
  description = "Public ip is the ip name that are connected to the firewall."
  type = string
}

variable "public_ip_prefix_length" {
  default = 30
  description = "Specifies the number of bits of the prefix. The value can be set between 24 (256 addresses) and 31 (2 addresses)."
  type = number
}

#
# NETWORK - SECURITY RULES
#

variable "dmz_nsg_rules" {
  description = "Network security rules to add to dmz subnet. See README for details on how to setup."
  type = list(any)
  default = []
}

variable "management_nsg_rules" {
  description = "Network security rules to add to management subnet. See README for details on how to setup."
  type = list(any)
  default = []
}

#
# PEERING
#

variable "peering_assignment" {
  description = "List of principal ids that should have access to peer to this Hub network. All service principals used to deploy spoke networks should have access to peer."
  type = list(string)
  default = []
}

#
# SUBSCRIPTIONS
#

variable "subscription_production" {
    description = "The subscription ID of the production subscription. Used to find the log analytics resources."
    type = string
}

variable "subscription_test" {
    description = "The subscription ID of the test subscription."
    type = string
}

#
# TAGS
#

variable "tags" {
  description = "Tags to apply to all resources created."
  type = map(string)
  default = { }
}
