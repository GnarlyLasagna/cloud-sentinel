
provider "google" {
  credentials = file("/Users/evandolatowski/cloudsentinel-sa.json")
  project     = "cloud-sentinel-gcp"
  region      = var.region
}

# VARIABLES
variable "region" {
  default = "us-central1"
}

variable "zone" {
  default = "us-central1-c"
}

# RANDOM SUFFIX (for unique names)
resource "random_id" "suffix" {
  byte_length = 4
}

# COMPUTE INSTANCE (VULNERABLE)
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
    access_config {} # Public IP (VULNERABLE)
  }

  tags = ["cloudsentinel"]
}

# FIREWALL RULE (OPEN SSH)
resource "google_compute_firewall" "open_ssh" {
  name    = "cloudsentinel-open-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"] # Open to internet

  target_tags = ["cloudsentinel"]
}

# STORAGE BUCKET (PUBLIC)
resource "google_storage_bucket" "public_bucket" {
  name                        = "cloudsentinel-public-${random_id.suffix.hex}"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = false
}

# Make bucket publicly accessible
resource "google_storage_bucket_iam_member" "public_access" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers" # Public access

}



# OPTIONAL: GLOBAL SSH KEYS (ADVANCED VULN)
resource "google_compute_project_metadata" "ssh_keys" {
  metadata = {
    ssh-keys = "cloudsentinel:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDexamplekey"
  }
}
