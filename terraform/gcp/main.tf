provider "google" {
  credentials = file("/Users/evandolatowski/cloudsentinel-sa.json")
  project     = "cloud-sentinel-gcp"
  region      = var.region
}


variable "region" {
  default = "us-central1"
}

variable "zone" {
  default = "us-central1-c"  # try c, f, or another available zone
}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "google_compute_instance" "vm" {
  name         = "cloudsentinel-vm"
  machine_type = "e2-micro"
  zone         = var.zone

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network       = "default"
    access_config {} # public IP
  }
}

resource "google_storage_bucket" "public_bucket" {
  name                        = "cloudsentinel-public-${random_id.suffix.hex}"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = false
}

