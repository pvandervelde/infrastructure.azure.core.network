# infrastructure.azure.core.network.hub

The `infrastructure.azure.core.network.hub` repository stores the resource configuration files for
[Terraform](https://www.terraform.io/) to deploy a
[resource group](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/overview#terminology) containing the hub part of a hub-and-spoke network using the [Microsoft recommended Hub-Spoke network topology](https://docs.microsoft.com/en-us/azure/architecture/reference-architectures/hybrid-networking/hub-spoke) to an Azure subscription.

The Terraform configuration creates the following group of resources:

![Resources created](./doc/resources.png)

* One resource group to contain all the resources
* A [key vault]()
* A [storage account]()
* The [virtual network]()
* Diagnostics for the vnet
* [Role assignment]() - To alow users to connect a Spoke network to peer with the Hub network.
* Subnets
  * Firewall - `AzureFirewallSubnet`
  * Gateway - `GatewaySubnet`
  * Management - `<PREFIX>-sn-management`
  * DMZ - `<PREFIX>-sn-dmz`
* Route table
  * Route table association to subnet management
  * Route table association to subnet dmz
* Network security groups
  * For subnet management
  * For subnet dmz
* Network watcher logs
  * For subnet management
  * For subnet dmz
* Azure monitor diagnostics
  * For subnet management
  * For subnet dmz
* Private DNS for the hub

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


### Setting up additional Network Security rules

FOR DMZ AND MANAGEMENT

## Use

In order to run the Terraform configuration in this repository you need to have an Azure subscription and be [connected to that subscription](https://www.terraform.io/docs/providers/azurerm/index.html).

Once you are signed in run the Terraform [plan](https://www.terraform.io/docs/commands/plan.html) command to preview the changes that will be made.

    tf plan -out ./build/tf/plan

When you are happy with the plan execute the plan with the Terraform [apply](https://www.terraform.io/docs/commands/apply.html) command.

    tf apply ./build/tf/plan
