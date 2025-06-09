import Foundation
import SwiftUI

@MainActor
@Observable
class KeycloakConfig {
    var keycloakBaseURL: String = "https://your-keycloak-server.com" {
        didSet { save() }
    }
    var realm: String = "your-realm" {
        didSet { save() }
    }
    var clientId: String = "your-client-id" {
        didSet { save() }
    }
    var redirectURI: String = "yourapp://oauth/callback" {
        didSet { save() }
    }
    
    // Optional: Add client secret if using confidential client
    // var clientSecret: String = "your-client-secret" {
    //     didSet { save() }
    // }
    
    private let userDefaults = UserDefaults.standard
    private let configKey = "KeycloakConfiguration"
    
    init() {
        load()
    }
    
    private func load() {
        if let data = userDefaults.data(forKey: configKey),
           let decoded = try? JSONDecoder().decode(ConfigData.self, from: data) {
            self.keycloakBaseURL = decoded.keycloakBaseURL
            self.realm = decoded.realm
            self.clientId = decoded.clientId
            self.redirectURI = decoded.redirectURI
        }
    }
    
    private func save() {
        let configData = ConfigData(
            keycloakBaseURL: keycloakBaseURL,
            realm: realm,
            clientId: clientId,
            redirectURI: redirectURI
        )
        
        if let encoded = try? JSONEncoder().encode(configData) {
            userDefaults.set(encoded, forKey: configKey)
        }
    }
    
    func reset() {
        keycloakBaseURL = "https://your-keycloak-server.com"
        realm = "your-realm"
        clientId = "your-client-id"
        redirectURI = "yourapp://oauth/callback"
        save()
    }
    
    var isConfigured: Bool {
        !keycloakBaseURL.isEmpty &&
        !realm.isEmpty &&
        !clientId.isEmpty &&
        !redirectURI.isEmpty &&
        keycloakBaseURL != "https://your-keycloak-server.com"
    }
}

private struct ConfigData: Codable {
    let keycloakBaseURL: String
    let realm: String
    let clientId: String
    let redirectURI: String
}
