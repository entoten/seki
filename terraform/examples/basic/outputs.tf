output "client_id" {
  description = "The ID of the provisioned OAuth client"
  value       = jsondecode(restapi_object.app_client.api_data).id
}

output "org_slug" {
  description = "The slug of the provisioned organization"
  value       = jsondecode(restapi_object.acme_org.api_data).slug
}
