output "database_url" {
  description = "Primary Postgres DSN (→ RECUPERO_DATABASE_URL)"
  value       = "postgresql://recupero:${random_password.db.result}@${aws_db_instance.primary.endpoint}/recupero"
  sensitive   = true
}

output "database_replica_endpoint" {
  description = "Read-replica endpoint for report/read-heavy traffic"
  value       = var.db_create_replica ? aws_db_instance.replica[0].endpoint : null
}

output "redis_url" {
  description = "Redis DSN (→ RECUPERO_REDIS_URL: shared rate-limit + api-key cache)"
  value       = "redis://${aws_elasticache_cluster.redis.cache_nodes[0].address}:6379/0"
}

output "artifact_bucket" {
  description = "S3 artifacts bucket (→ RECUPERO_ARTIFACT_BUCKET)"
  value       = aws_s3_bucket.artifacts.bucket
}

output "app_secret_arn" {
  description = "Secrets Manager ARN holding the app env (mount via the k8s CSI secrets-store driver)"
  value       = aws_secretsmanager_secret.app.arn
}
