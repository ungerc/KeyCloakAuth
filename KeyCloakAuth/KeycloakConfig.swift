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
    var redirectURI: String {
        // Load from Info.plist
        if let urlTypes = Bundle.main.infoDictionary?["CFBundleURLTypes"] as? [[String: Any]],
           let urlType = urlTypes.first,
           let urlSchemes = urlType["CFBundleURLSchemes"] as? [String],
           let scheme = urlSchemes.first {
            return "\(scheme)://oauth/callback"
        }
        return "yourapp://oauth/callback"
    }
    
    var urlScheme: String {
        // Extract the URL scheme from Info.plist
        if let urlTypes = Bundle.main.infoDictionary?["CFBundleURLTypes"] as? [[String: Any]],
           let urlType = urlTypes.first,
           let urlSchemes = urlType["CFBundleURLSchemes"] as? [String],
           let scheme = urlSchemes.first {
            return scheme
        }
        return "yourapp"
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
        }
    }
    
    private func save() {
        let configData = ConfigData(
            keycloakBaseURL: keycloakBaseURL,
            realm: realm,
            clientId: clientId
        )
        
        if let encoded = try? JSONEncoder().encode(configData) {
            userDefaults.set(encoded, forKey: configKey)
        }
    }
    
    func reset() {
        keycloakBaseURL = "https://your-keycloak-server.com"
        realm = "your-realm"
        clientId = "your-client-id"
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
}
