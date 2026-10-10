# nimbus cloud lab: Azure stub (S10 public blob, S11 RDP -> VM -> managed identity Contributor).
# UNVERIFIED: never planned or applied; no Azure lab subscription exists yet.
terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

variable "nimbus_e2e" {
  type = string
  validation {
    condition     = var.nimbus_e2e == "1"
    error_message = "Refusing to build a deliberately vulnerable lab without nimbus_e2e=1."
  }
}
variable "subscription_id" { type = string }
variable "location" {
  type    = string
  default = "eastus"
}
variable "cost_ceiling_usd" {
  type    = number
  default = 25
}
variable "expires_at" { type = string }

locals {
  tags = { nimbus_lab = "true", cost_ceiling_usd = tostring(var.cost_ceiling_usd), expires_at = var.expires_at }
}

resource "azurerm_resource_group" "lab" {
  name     = "nimbus-lab-rg"
  location = var.location
  tags     = local.tags
}

# S10
resource "azurerm_storage_account" "hr" {
  name                            = "nimbuslabhrexports"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  allow_nested_items_to_be_public = true
  tags                            = merge(local.tags, { data_classification = "confidential", environment = "production" })
}

resource "azurerm_storage_container" "exports" {
  name                  = "exports"
  storage_account_id    = azurerm_storage_account.hr.id
  container_access_type = "blob"
}

# S11 (VM itself is left as a sketch to keep the stub cheap; NSG + identity are real)
resource "azurerm_network_security_group" "jump" {
  name                = "nimbus-lab-jump-nsg"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  security_rule {
    name                       = "allow-rdp-any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  tags = local.tags
}

resource "azurerm_user_assigned_identity" "jump" {
  name                = "nimbus-lab-jump-mi"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_role_assignment" "jump_contributor" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.jump.principal_id
}

# TODO(cloud lab): azurerm_windows_virtual_machine "nimbus-lab-jump-01" with a public IP, the NSG
# on its NIC, and identity { type = "UserAssigned", identity_ids = [azurerm_user_assigned_identity.jump.id] }.
