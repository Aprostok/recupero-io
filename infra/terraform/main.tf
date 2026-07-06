###############################################################################
# Recupero SaaS data plane — Postgres, Redis, object storage, secrets.
#
# The compute plane (API + worker + scheduler) lives in infra/k8s; this module
# provisions the stateful dependencies and emits their endpoints/DSNs as outputs
# that materialise the k8s Secret.
#
# NOTE: this is a production-shaped starting point — review sizing, backup
# windows, deletion protection, and network (VPC/subnets/SGs are referenced as
# data sources; wire to your existing VPC or add a vpc module) before apply.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.5" }
  }
}

provider "aws" {
  region = var.region
}

locals {
  name = "${var.project}-${var.environment}"
  tags = merge({ Project = var.project, Environment = var.environment, ManagedBy = "terraform" }, var.tags)
}

# ── networking (use the default VPC's private subnets; swap for your own) ────
data "aws_vpc" "main" { default = true }

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }
}

resource "aws_security_group" "data" {
  name        = "${local.name}-data"
  description = "Recupero data plane (Postgres + Redis), reachable only from the cluster SG"
  vpc_id      = data.aws_vpc.main.id
  tags        = local.tags
}

# ── Postgres (primary + optional read replica) ───────────────────────────────
resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db"
  subnet_ids = data.aws_subnets.private.ids
  tags       = local.tags
}

resource "aws_db_instance" "primary" {
  identifier                 = "${local.name}-pg"
  engine                     = "postgres"
  engine_version             = "16"
  instance_class             = var.db_instance_class
  allocated_storage          = var.db_allocated_storage_gb
  max_allocated_storage      = var.db_allocated_storage_gb * 5
  storage_type               = "gp3"
  storage_encrypted          = true
  db_name                    = "recupero"
  username                   = "recupero"
  password                   = random_password.db.result
  db_subnet_group_name       = aws_db_subnet_group.main.name
  vpc_security_group_ids     = [aws_security_group.data.id]
  multi_az                   = true
  backup_retention_period    = 14
  deletion_protection        = true
  auto_minor_version_upgrade = true
  skip_final_snapshot        = false
  final_snapshot_identifier  = "${local.name}-pg-final"
  tags                       = local.tags
}

resource "aws_db_instance" "replica" {
  count               = var.db_create_replica ? 1 : 0
  identifier          = "${local.name}-pg-ro"
  instance_class      = var.db_instance_class
  replicate_source_db = aws_db_instance.primary.identifier
  storage_encrypted   = true
  skip_final_snapshot = true
  tags                = local.tags
}

# ── Redis (rate-limit + api-key cache; both fail open) ────────────────────────
resource "aws_elasticache_subnet_group" "main" {
  name       = "${local.name}-redis"
  subnet_ids = data.aws_subnets.private.ids
}

resource "aws_elasticache_cluster" "redis" {
  cluster_id           = "${local.name}-redis"
  engine               = "redis"
  node_type            = var.redis_node_type
  num_cache_nodes      = 1
  parameter_group_name = "default.redis7"
  port                 = 6379
  subnet_group_name    = aws_elasticache_subnet_group.main.name
  security_group_ids   = [aws_security_group.data.id]
  tags                 = local.tags
}

# ── S3 artifacts bucket (per-org key prefix + retention lifecycle) ────────────
resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name}-artifacts"
  tags   = local.tags
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    id     = "expire-artifacts"
    status = "Enabled"
    filter { prefix = "orgs/" }
    expiration { days = var.artifact_retention_days }
  }
}

# ── secrets (endpoints wired into the k8s Secret via outputs) ─────────────────
resource "aws_secretsmanager_secret" "app" {
  name = "${local.name}-app"
  tags = local.tags
}

resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    RECUPERO_DATABASE_URL    = "postgresql://recupero:${random_password.db.result}@${aws_db_instance.primary.endpoint}/recupero"
    RECUPERO_REDIS_URL       = "redis://${aws_elasticache_cluster.redis.cache_nodes[0].address}:6379/0"
    RECUPERO_ARTIFACT_BUCKET = aws_s3_bucket.artifacts.bucket
    RECUPERO_ARTIFACT_REGION = var.region
  })
}
