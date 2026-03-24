variable "seki_url" {
  description = "Base URL of the seki server"
  type        = string
  default     = "http://localhost:8080"
}

variable "seki_api_key" {
  description = "Admin API key for authenticating with seki"
  type        = string
  sensitive   = true
}
