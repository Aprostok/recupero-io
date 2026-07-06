variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Resource name prefix"
  type        = string
  default     = "recupero"
}

variable "environment" {
  description = "Deployment environment (prod | staging)"
  type        = string
  default     = "prod"
}

variable "db_instance_class" {
  type    = string
  default = "db.r6g.large"
}

variable "db_allocated_storage_gb" {
  type    = number
  default = 100
}

variable "db_create_replica" {
  description = "Provision a read replica for report/read-heavy traffic"
  type        = bool
  default     = true
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}

variable "artifact_retention_days" {
  description = "S3 lifecycle expiry for case artifacts (backstop to the app's per-plan retention cron)"
  type        = number
  default     = 400
}

variable "tags" {
  type    = map(string)
  default = {}
}
