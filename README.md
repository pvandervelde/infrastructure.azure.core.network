# infrastructure.azure.core.network.hub

The `infrastructure.azure.core.network.hub` repository stores the resource configuration files for
[Terraform](https://www.terraform.io/) to deploy a
[resource group](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/overview#terminology) containing the hub part of a hub-and-spoke network using the [Microsoft recommended Hub-Spoke network topology](https://docs.microsoft.com/en-us/azure/architecture/reference-architectures/hybrid-networking/hub-spoke) to an Azure subscription.

The Terraform code in this repository is based on the [Hub repository](https://github.com/avinor/terraform-azurerm-virtual-network-hub)
by [avinor](https://github.com/avinor)

The Terraform configuration creates the following group of resources:

![Resources created](./doc/resources.png)

* One resource group to contain all the resources.
* A [key vault](https://docs.microsoft.com/en-us/azure/key-vault/general/overview).
* A [storage account](https://docs.microsoft.com/en-us/azure/storage/common/storage-account-overview)
  to store the flow logs created by the
  [Network Watcher](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview).
* The [virtual network](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview)
  for the hub.
* Role assignments that alow users to connect a Spoke network to peer with the Hub network.
* Several subnet instances for:
  * The Firewall - Named: `AzureFirewallSubnet`
  * The VPN Gateway - Named: `GatewaySubnet`
  * A Management area - Named: `<PREFIX>-sn-management`
  * A DMZ area - Named: `<PREFIX>-sn-dmz`
* [Route table](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview) and associated entries to:
  * The management subnet
  * The DMZ subnet
* [Network security groups](https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
  for:
  * The management subnet
  * The DMZ subnet
* [Network Watcher](https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview) logs for:
  * The management subnet
  * The DMZ subnet
* Azure monitor diagnostics settings for:
  * The management subnet
  * The DMZ subnet
* [Private DNS](https://docs.microsoft.com/en-us/azure/dns/private-dns-overview)
  that allows resources in the hub network and peered spoke networks to resolve
  internal IP addresses.

Most resources are named after the type of resource they are, e.g. `-rg` for the resource group, prefixed with a standard prefix. The prefix consists of
a combination of the Environment, e.g. Production, the Azure location,
e.g. Australia East, and a category, in this case `nwk-hub`:

    ${var.environment_short}-${var.location_short}-tf-${var.category}

The default values for each of the variables are defined in the `variables.tf` file

* `environment_short` = `p` - For production
* `location_short` = `aue` - For the Australia East region
* `category` = `nwk-hub`

Which leads to a prefix of: `p-aue-tf-nwk-hub`

By default the following tags are added:

* **category** - Set to the category. Defaults to `nwk-hub`
* **environment** - Set to the environment. Defaults to `production`
* **location** - The Azure region in which the resources are created. Defaults to `australiaeast`
* **source** - The commit ID of the current commit
* **version** - The version of the resources

Additional tags can be added by setting the `tags` variable as defined in the `variables.tf` file.

## Variables

* **category** - The name of the category that all the resources are running in. Defaults to `nwk-hub`
* **environment** - The name of the environment that all the resources are running in. Defaults to `production`
* **location** - The full name of the Azure region in which the resources should be created. Defaults to `australiaeast`
* **meta_source** - The commit ID of the current commit from which the plan is being created. Used to tag the resources.
* **meta_version** - The version of the infrastructure as it is being generated. Used to tag the resources.
* **address_space** - The full address space that is used the virtual network. Requires at least a /24 address space. Defaults to `10.1.1.0/24`.
* **private_dns_zone** - Name of private dns zone to create and associate with virtual network. Defaults to `hub.azure.calvinverse.net`. As per the [standard guidance]() it is suggested to use a subdomain of a domain that is registered to you.
* **dmz_nsg_rules** - Network security rules to add to dmz subnet.
* **management_nsg_rules** - Network security rules to add to management subnet.
* **peering_assignment** - List of principal ids that should have access to peer to this Hub network. All service principals used to deploy spoke networks should have access to peer.
* **subscription_production** - The subscription ID of the production subscription. Used to find the log analytics resources.
* **subscription_test** - The subscription ID of the test subscription.
* **tags** - Tags to apply to all resources created.

## Use

In order to run the Terraform configuration in this repository you need to have an Azure subscription and be [connected to that subscription](https://www.terraform.io/docs/providers/azurerm/index.html).

Once you are signed in run the Terraform [plan](https://www.terraform.io/docs/commands/plan.html) command to preview the changes that will be made.

    tf plan -var subscription_production=<SUBSCRIPTION_ID> -var subscription_test=<SUBSCRIPTION_ID> -var meta_source=<GIT_COMMIT_HASH> -var meta_version=<VERSION> -out ./build/tf/plan

When you are happy with the plan execute the plan with the Terraform [apply](https://www.terraform.io/docs/commands/apply.html) command.

    tf apply ./build/tf/plan
