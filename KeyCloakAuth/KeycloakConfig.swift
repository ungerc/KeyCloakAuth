import Foundation

struct KeycloakConfig {
    // TODO: Replace these with your actual Keycloak configuration
    let keycloakBaseURL = "https://your-keycloak-server.com"
    let realm = "your-realm"
    let clientId = "your-client-id"
    let redirectURI = "yourapp://oauth/callback"
    
    // Optional: Add client secret if using confidential client
    // let clientSecret = "your-client-secret"
}
