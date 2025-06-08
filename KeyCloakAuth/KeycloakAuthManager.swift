import Foundation
import SwiftUI

@MainActor
class KeycloakAuthManager: ObservableObject {
    @Published var isAuthenticated = false
    @Published var accessToken: String?
    @Published var refreshToken: String?
    
    let config = KeycloakConfig()
    
    func getAuthorizationURL() -> URL? {
        var components = URLComponents(string: "\(config.keycloakBaseURL)/auth/realms/\(config.realm)/protocol/openid-connect/auth")
        
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: "openid profile email"),
            URLQueryItem(name: "state", value: UUID().uuidString),
            URLQueryItem(name: "nonce", value: UUID().uuidString)
        ]
        
        return components?.url
    }
    
    func handleAuthorizationCode(_ code: String) async {
        do {
            let tokens = try await exchangeCodeForTokens(code: code)
            self.accessToken = tokens.accessToken
            self.refreshToken = tokens.refreshToken
            self.isAuthenticated = true
        } catch {
            print("Error exchanging code for tokens: \(error)")
        }
    }
    
    private func exchangeCodeForTokens(code: String) async throws -> TokenResponse {
        let tokenURL = URL(string: "\(config.keycloakBaseURL)/auth/realms/\(config.realm)/protocol/openid-connect/token")!
        
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        let parameters = [
            "grant_type": "authorization_code",
            "client_id": config.clientId,
            "code": code,
            "redirect_uri": config.redirectURI
        ]
        
        let bodyString = parameters
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
        
        request.httpBody = bodyString.data(using: .utf8)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        
        return tokenResponse
    }
    
    func logout() {
        accessToken = nil
        refreshToken = nil
        isAuthenticated = false
        
        // In a real app, you would also call the Keycloak logout endpoint
        // and clear any stored tokens from keychain
    }
}

struct TokenResponse: Codable {
    let accessToken: String
    let refreshToken: String?
    let expiresIn: Int
    let tokenType: String
    
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
    }
}
