# =====================================
# CloudSentinel Azure Vulnerable Infrastructure
# Free Tier Friendly
# =====================================



terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
    }
  }
}

provider "azurerm" {
  features {}
}

# RESOURCE GROUP
resource "azurerm_resource_group" "rg" {
  name     = "cloudsentinel-rg"
  location = "centralus"
}

# NETWORK (VULNERABLE)
resource "azurerm_virtual_network" "vnet" {
  name                = "cloudsentinel-vnet"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "subnet" {
  name                 = "cloudsentinel-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

# NSG (VULNERABILITY #1)
resource "azurerm_network_security_group" "nsg" {
  name                = "cloudsentinel-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "allow-all-inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"  
    destination_address_prefix = "*"
  }
}

# STORAGE (VULNERABILITY #2)
resource "random_id" "suffix" {
  byte_length = 2
}

resource "azurerm_storage_account" "storage" {
  name                     = "cs${random_id.suffix.hex}store"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "public" {
  name                  = "public-container"
  storage_account_name  = azurerm_storage_account.storage.name
  container_access_type = "blob" # 
}
