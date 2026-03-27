# =====================================
# CloudSentinel Azure Vulnerable Infrastructure
# Free Tier Friendly
# =====================================

# PROVIDER
provider "google" {
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

# RANDOM SUFFIX
resource "random_id" "suffix" {
  byte_length = 4
}

# ENABLE REQUIRED APIS
resource "google_project_service" "apis" {
  for_each = toset([
    "iam.googleapis.com",
    "compute.googleapis.com",
    "storage.googleapis.com",
    "cloudresourcemanager.googleapis.com"
  ])

  project = "cloud-sentinel-gcp"
  service = each.value

  disable_on_destroy = false
}

# SERVICE ACCOUNT (IAM MISCONFIG)
resource "google_service_account" "lab_sa" {
  account_id   = "cloudsentinel-sa"
  display_name = "CloudSentinel Lab Service Account"

  depends_on = [google_project_service.apis]
}


# COMPUTE INSTANCES

# VM 1 (tagged + public)
resource "google_compute_instance" "vm1" {
  name         = "cloudsentinel-vm"
  machine_type  = "e2-micro"
  zone          = var.zone

  depends_on = [google_project_service.apis]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network       = "default"
    access_config {}
  }

  tags = ["cloudsentinel"]

  service_account {
    email  = google_service_account.lab_sa.email
    scopes = ["cloud-platform"]
  }
}

# VM 2 (untagged → firewall bypass)
resource "google_compute_instance" "vm2" {
  name         = "cloudsentinel-vm-2"
  machine_type  = "e2-micro"
  zone          = var.zone

  depends_on = [google_project_service.apis]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network       = "default"
    access_config {}
  }
}

# FIREWALL RULES

# SSH OPEN (targeted)
resource "google_compute_firewall" "ssh_open" {
  name    = "cloudsentinel-ssh-open"
  network = "default"

  depends_on = [google_project_service.apis]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["cloudsentinel"]
}

# FULLY OPEN FIREWALL (high risk)
resource "google_compute_firewall" "open_all" {
  name    = "cloudsentinel-open-all"
  network = "default"

  depends_on = [google_project_service.apis]

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# STORAGE BUCKETS

# PUBLIC BUCKET
resource "google_storage_bucket" "public_bucket" {
  name     = "cloudsentinel-public-${random_id.suffix.hex}"
  location = var.region

  force_destroy = true

  uniform_bucket_level_access = false

  depends_on = [google_project_service.apis]
}

resource "google_storage_bucket_iam_member" "public_access" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"

  depends_on = [google_project_service.apis]
}

# PRIVATE BUCKET (for comparison checks)
resource "google_storage_bucket" "private_bucket" {
  name     = "cloudsentinel-private-${random_id.suffix.hex}"
  location = var.region

  force_destroy = true
  uniform_bucket_level_access = true

  depends_on = [google_project_service.apis]
}

# DISKS

# UNATTACHED DISK
resource "google_compute_disk" "unattached_disk" {
  name  = "cloudsentinel-orphan-disk"
  type  = "pd-standard"
  zone  = var.zone
  size  = 10

  depends_on = [google_project_service.apis]
}

# STATIC IP

resource "google_compute_address" "static_ip" {
  name = "cloudsentinel-static-ip"

  depends_on = [google_project_service.apis]
}

