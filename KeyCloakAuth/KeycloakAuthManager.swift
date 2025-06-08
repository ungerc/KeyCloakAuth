import Foundation
import SwiftUI
import CryptoKit

@MainActor
class KeycloakAuthManager: ObservableObject {
    @Published var isAuthenticated = false
    @Published var accessToken: String?
    @Published var refreshToken: String?
    @Published var isSecureEnclaveAvailable = false
    
    let config = KeycloakConfig()
    private let secureEnclaveManager = SecureEnclaveManager.shared
    private var codeVerifier: String?
    private var codeChallenge: String?
    
    init() {
        checkSecureEnclaveAvailability()
        setupSecureEnclaveKey()
    }
    
    private func checkSecureEnclaveAvailability() {
        isSecureEnclaveAvailable = SecureEnclave.isAvailable
    }
    
    private func setupSecureEnclaveKey() {
        guard isSecureEnclaveAvailable else { return }
        
        do {
            try secureEnclaveManager.generateKeyPairs()
            print("Secure Enclave key pairs generated or loaded successfully")
        } catch {
            print("Failed to setup Secure Enclave keys: \(error)")
        }
    }
    
    func getAuthorizationURL() -> URL? {
        // Generate PKCE parameters with Secure Enclave enhancement
        let (verifier, challenge) = generatePKCEParameters()
        self.codeVerifier = verifier
        self.codeChallenge = challenge
        
        var components = URLComponents(string: "\(config.keycloakBaseURL)/auth/realms/\(config.realm)/protocol/openid-connect/auth")
        
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: "openid profile email"),
            URLQueryItem(name: "state", value: generateSecureState()),
            URLQueryItem(name: "nonce", value: UUID().uuidString),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]
        
        return components?.url
    }
    
    private func generatePKCEParameters() -> (verifier: String, challenge: String) {
        // Generate a secure code verifier
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let verifier = Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        
        // If Secure Enclave is available, enhance the challenge with a signature
        var challenge: String
        if isSecureEnclaveAvailable {
            do {
                // Sign the verifier with Secure Enclave key
                let signature = try secureEnclaveManager.signData(Data(verifier.utf8))
                let enhancedData = Data(verifier.utf8) + signature
                
                // Create challenge from enhanced data
                let hash = SHA256.hash(data: enhancedData)
                challenge = Data(hash).base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
            } catch {
                // Fallback to standard PKCE
                print("Secure Enclave signing failed, using standard PKCE: \(error)")
                let hash = SHA256.hash(data: Data(verifier.utf8))
                challenge = Data(hash).base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
            }
        } else {
            // Standard PKCE challenge
            let hash = SHA256.hash(data: Data(verifier.utf8))
            challenge = Data(hash).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        
        return (verifier, challenge)
    }
    
    private func generateSecureState() -> String {
        let state = UUID().uuidString
        
        // If Secure Enclave is available, sign the state
        if isSecureEnclaveAvailable {
            do {
                let signature = try secureEnclaveManager.signData(Data(state.utf8))
                let signedState = state + "." + signature.base64EncodedString()
                return signedState
            } catch {
                print("Failed to sign state with Secure Enclave: \(error)")
            }
        }
        
        return state
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
        
        var parameters = [
            "grant_type": "authorization_code",
            "client_id": config.clientId,
            "code": code,
            "redirect_uri": config.redirectURI
        ]
        
        // Add PKCE code verifier
        if let verifier = codeVerifier {
            parameters["code_verifier"] = verifier
        }
        
        // If Secure Enclave is available, add client assertion
        if isSecureEnclaveAvailable {
            if let assertion = try? createClientAssertion() {
                parameters["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                parameters["client_assertion"] = assertion
            }
        }
        
        let bodyString = parameters
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
        
        request.httpBody = bodyString.data(using: .utf8)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        
        return tokenResponse
    }
    
    private func createClientAssertion() throws -> String? {
        // Create a JWT assertion signed with Secure Enclave key
        let header = [
            "alg": "ES256",
            "typ": "JWT"
        ]
        
        let now = Date()
        let claims: [String: Any] = [
            "iss": config.clientId,
            "sub": config.clientId,
            "aud": "\(config.keycloakBaseURL)/auth/realms/\(config.realm)",
            "iat": Int(now.timeIntervalSince1970),
            "exp": Int(now.addingTimeInterval(300).timeIntervalSince1970),
            "jti": UUID().uuidString
        ]
        
        // Convert to JSON and base64
        let headerData = try JSONSerialization.data(withJSONObject: header)
        let claimsData = try JSONSerialization.data(withJSONObject: claims)
        
        let headerBase64 = headerData.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        
        let claimsBase64 = claimsData.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        
        let message = "\(headerBase64).\(claimsBase64)"
        
        // Sign with Secure Enclave
        let signature = try secureEnclaveManager.signData(Data(message.utf8))
        let signatureBase64 = signature.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        
        return "\(message).\(signatureBase64)"
    }
    
    func logout() {
        accessToken = nil
        refreshToken = nil
        isAuthenticated = false
        codeVerifier = nil
        codeChallenge = nil
        
        // In a real app, you would also call the Keycloak logout endpoint
        // and clear any stored tokens from keychain
    }
    
    /// Store tokens securely using derived encryption key
    func securelyStoreTokens(_ tokens: TokenResponse) async throws {
        guard isSecureEnclaveAvailable else {
            // Fallback to standard storage
            self.accessToken = tokens.accessToken
            self.refreshToken = tokens.refreshToken
            return
        }
        
        // Derive encryption key from Secure Enclave
        let salt = Data(UUID().uuidString.utf8)
        let info = Data("keycloak-token-encryption".utf8)
        let encryptionKey = try secureEnclaveManager.deriveSymmetricKey(salt: salt, info: info)
        
        // Encrypt tokens
        let tokenData = try JSONEncoder().encode(tokens)
        let sealedBox = try AES.GCM.seal(tokenData, using: encryptionKey)
        
        // Store encrypted tokens (in a real app, use Keychain)
        // For now, just store in memory
        self.accessToken = tokens.accessToken
        self.refreshToken = tokens.refreshToken
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
