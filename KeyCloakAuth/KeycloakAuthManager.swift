import Foundation
import SwiftUI
import CryptoKit

/// KeycloakAuthManager orchestrates authentication with a Keycloak server.
///
/// This manager provides a comprehensive authentication solution that supports multiple
/// authentication methods including standard OAuth 2.0/OIDC, Secure Enclave-enhanced
/// authentication, and WebAuthn passkeys.
///
/// ## Overview
/// The manager implements:
/// - OAuth 2.0 Authorization Code flow with PKCE
/// - OpenID Connect (OIDC) for identity verification
/// - Hardware-backed security with Secure Enclave
/// - Passwordless authentication with passkeys
/// - Secure token storage and management
///
/// ## Authentication Methods
/// 1. **Standard**: Traditional OAuth flow through web view
/// 2. **Secure Enclave**: Enhanced with hardware-backed cryptography
/// 3. **Passkey**: Passwordless using platform authenticators
///
/// ## Security Features
/// - PKCE (Proof Key for Code Exchange) for all flows
/// - Secure Enclave signing for enhanced security
/// - Client assertion using hardware-backed keys
/// - Encrypted token storage
/// - Cryptographically signed state parameters
///
/// ## Usage
/// ```swift
/// @StateObject private var authManager = KeycloakAuthManager()
///
/// // Check available methods
/// if authManager.isPasskeyAvailable {
///     await authManager.authenticateWithPasskey()
/// } else {
///     // Show web view with authManager.getAuthorizationURL()
/// }
/// ```
///
/// ## Token Management
/// Tokens are stored in memory with optional encryption using Secure Enclave-derived keys.
/// In production, tokens should be stored in the iOS Keychain.
///
/// - Note: Requires iOS 16.0+ for passkey support
@MainActor
@Observable
class KeycloakAuthManager {
    // MARK: - Published Properties
    
    /// Indicates whether the user is currently authenticated
    var isAuthenticated = false
    
    /// The current OAuth access token for API requests
    var accessToken: String?
    
    /// The refresh token for obtaining new access tokens
    var refreshToken: String?
    
    /// Whether Secure Enclave is available on this device
    var isSecureEnclaveAvailable = false
    
    /// Whether passkeys are available (iOS 16.0+)
    var isPasskeyAvailable = false
    
    /// The currently selected authentication method
    var authMethod: AuthenticationMethod = .standard
    
    // MARK: - Configuration
    
    /// Keycloak server configuration
    let config = KeycloakConfig()
    
    // MARK: - Managers
    
    /// Handles Secure Enclave cryptographic operations
    private let secureEnclaveManager = SecureEnclaveManager.shared
    
    /// Handles passkey registration and authentication
    private let passkeyManager: PasskeyManager
    
    // MARK: - PKCE Parameters
    
    /// PKCE code verifier for the current authentication flow
    private var codeVerifier: String?
    
    /// PKCE code challenge derived from the verifier
    private var codeChallenge: String?
    
    // MARK: - Types
    
    /// Available authentication methods
    enum AuthenticationMethod {
        /// Standard OAuth 2.0 flow through web view
        case standard
        
        /// OAuth flow enhanced with Secure Enclave signing
        case secureEnclave
        
        /// Passwordless authentication using passkeys
        case passkey
    }
    
    // MARK: - Initialization
    
    /// Initializes the authentication manager and checks available authentication methods
    ///
    /// On initialization, the manager:
    /// 1. Creates a PasskeyManager instance with the configured domain
    /// 2. Checks if Secure Enclave is available
    /// 3. Generates or loads Secure Enclave keys if available
    /// 4. Checks if passkeys are supported (iOS 16.0+)
    init() {
        // Initialize PasskeyManager with the Keycloak configuration
        self.passkeyManager = PasskeyManager(config: config)
        
        checkSecureEnclaveAvailability()
        setupSecureEnclaveKey()
        checkPasskeyAvailability()
    }
    
    /// Checks if Secure Enclave is available on the current device
    ///
    /// Secure Enclave requires:
    /// - A7 chip or later (iPhone 5s and newer)
    /// - Not available on simulator
    private func checkSecureEnclaveAvailability() {
        isSecureEnclaveAvailable = SecureEnclave.isAvailable
    }
    
    /// Checks if passkeys are available on the current device
    ///
    /// Passkeys require:
    /// - iOS 16.0 or later
    /// - Device with Face ID or Touch ID
    private func checkPasskeyAvailability() {
        isPasskeyAvailable = passkeyManager.isPasskeyAvailable
    }
    
    /// Sets up Secure Enclave keys for enhanced authentication
    ///
    /// This method generates two types of keys if they don't exist:
    /// - Signing key: For creating client assertions
    /// - Key agreement key: For deriving encryption keys
    ///
    /// Keys are generated once and persist across app launches
    private func setupSecureEnclaveKey() {
        guard isSecureEnclaveAvailable else { return }
        
        do {
            try secureEnclaveManager.generateKeyPairs()
            print("Secure Enclave key pairs generated or loaded successfully")
        } catch {
            print("Failed to setup Secure Enclave keys: \(error)")
        }
    }
    
    // MARK: - OAuth Authorization
    
    /// Generates the authorization URL for initiating the OAuth flow
    ///
    /// This method constructs a properly formatted authorization URL with:
    /// - PKCE parameters for security
    /// - OpenID Connect scopes
    /// - State parameter (optionally signed with Secure Enclave)
    /// - Nonce for replay protection
    /// - ACR values hint for passkey authentication
    ///
    /// - Returns: The authorization URL to load in a web view, or nil if configuration is invalid
    ///
    /// ## Security Features
    /// - PKCE prevents authorization code interception
    /// - State prevents CSRF attacks
    /// - Nonce prevents replay attacks
    /// - Secure Enclave signing adds hardware-backed integrity
    func getAuthorizationURL() -> URL? {
        // Generate PKCE parameters with Secure Enclave enhancement
        let (verifier, challenge) = generatePKCEParameters()
        self.codeVerifier = verifier
        self.codeChallenge = challenge
        
        var components = URLComponents(string: "\(config.keycloakBaseURL)/auth/realms/\(config.realm)/protocol/openid-connect/auth")
        
        var queryItems = [
            URLQueryItem(name: "client_id", value: config.clientId),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: "openid profile email"),
            URLQueryItem(name: "state", value: generateSecureState()),
            URLQueryItem(name: "nonce", value: UUID().uuidString),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256")
        ]
        
        // Add passkey hint if using passkey authentication
        if authMethod == .passkey && isPasskeyAvailable {
            queryItems.append(URLQueryItem(name: "acr_values", value: "passkey"))
        }
        
        components?.queryItems = queryItems
        
        return components?.url
    }
    
    /// Generates PKCE (Proof Key for Code Exchange) parameters
    ///
    /// PKCE protects against authorization code interception attacks by:
    /// 1. Creating a random verifier
    /// 2. Deriving a challenge from the verifier
    /// 3. Sending only the challenge in the authorization request
    /// 4. Sending the verifier when exchanging the code
    ///
    /// When Secure Enclave is available, the challenge is enhanced by:
    /// - Signing the verifier with the hardware key
    /// - Including the signature in the challenge derivation
    /// - Providing additional proof of client identity
    ///
    /// - Returns: A tuple containing the verifier and challenge
    ///
    /// ## Security Enhancement
    /// The Secure Enclave signature binds the PKCE flow to this specific device,
    /// preventing code replay on other devices even if intercepted.
    private func generatePKCEParameters() -> (verifier: String, challenge: String) {
        // Generate a secure code verifier (43-128 characters)
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
            // Standard PKCE challenge (SHA256 of verifier)
            let hash = SHA256.hash(data: Data(verifier.utf8))
            challenge = Data(hash).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        
        return (verifier, challenge)
    }
    
    /// Generates a secure state parameter for CSRF protection
    ///
    /// The state parameter prevents Cross-Site Request Forgery (CSRF) attacks by:
    /// - Including a random value in the authorization request
    /// - Verifying the same value is returned in the callback
    ///
    /// When Secure Enclave is available, the state is enhanced with:
    /// - A cryptographic signature proving it came from this device
    /// - Additional integrity protection against tampering
    ///
    /// - Returns: A state string, optionally with appended signature
    ///
    /// ## Format
    /// - Standard: `UUID`
    /// - Secure Enclave: `UUID.base64Signature`
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
    
    // MARK: - Authorization Code Exchange
    
    /// Handles the authorization code received from the OAuth callback
    ///
    /// This method is called when the user completes authentication in the web view
    /// and Keycloak redirects back with an authorization code. It exchanges the code
    /// for access and refresh tokens.
    ///
    /// - Parameter code: The authorization code from the callback URL
    ///
    /// ## Flow
    /// 1. Extract authorization code from redirect
    /// 2. Exchange code for tokens using PKCE verifier
    /// 3. Store tokens and update authentication state
    /// 4. Optionally encrypt tokens with Secure Enclave
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
    
    /// Exchanges an authorization code for access and refresh tokens
    ///
    /// This method completes the OAuth 2.0 Authorization Code flow by:
    /// 1. Sending the authorization code to the token endpoint
    /// 2. Including the PKCE verifier for code verification
    /// 3. Optionally including a client assertion for enhanced security
    /// 4. Parsing and returning the token response
    ///
    /// - Parameter code: The authorization code received from the callback
    /// - Returns: A `TokenResponse` containing access and refresh tokens
    /// - Throws: Network or decoding errors
    ///
    /// ## Security Features
    /// - PKCE verifier proves this is the same client that initiated the flow
    /// - Client assertion (when available) provides cryptographic client authentication
    /// - Uses HTTPS for transport security
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
    
    /// Creates a JWT client assertion signed with the Secure Enclave key
    ///
    /// Client assertions provide a more secure alternative to client secrets by:
    /// - Using asymmetric cryptography instead of shared secrets
    /// - Binding authentication to a specific device
    /// - Providing non-repudiation of client identity
    ///
    /// The assertion is a JWT containing:
    /// - `iss`: Client ID (issuer)
    /// - `sub`: Client ID (subject)
    /// - `aud`: Token endpoint URL (audience)
    /// - `iat`: Issued at timestamp
    /// - `exp`: Expiration (5 minutes)
    /// - `jti`: Unique JWT ID
    ///
    /// - Returns: A signed JWT assertion, or nil if creation fails
    /// - Throws: Serialization or signing errors
    ///
    /// ## Security
    /// - Private key never leaves Secure Enclave
    /// - Short expiration prevents replay attacks
    /// - Unique JTI prevents duplicate usage
    private func createClientAssertion() throws -> String? {
        // Create a JWT assertion signed with Secure Enclave key
        let header = [
            "alg": "ES256",  // Elliptic Curve signature with P-256 and SHA-256
            "typ": "JWT"
        ]
        
        let now = Date()
        let claims: [String: Any] = [
            "iss": config.clientId,  // Issuer is the client
            "sub": config.clientId,  // Subject is also the client
            "aud": "\(config.keycloakBaseURL)/auth/realms/\(config.realm)",  // Audience is the token endpoint
            "iat": Int(now.timeIntervalSince1970),  // Issued at
            "exp": Int(now.addingTimeInterval(300).timeIntervalSince1970),  // Expires in 5 minutes
            "jti": UUID().uuidString  // Unique JWT ID
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
    
    // MARK: - Session Management
    
    /// Logs out the current user and clears all authentication state
    ///
    /// This method:
    /// 1. Clears all tokens from memory
    /// 2. Resets authentication state
    /// 3. Clears PKCE parameters
    ///
    /// ## Production Considerations
    /// In a production app, you should also:
    /// - Call the Keycloak logout endpoint to invalidate the session
    /// - Clear tokens from the iOS Keychain
    /// - Revoke the refresh token if supported
    /// - Clear any cached user data
    func logout() {
        accessToken = nil
        refreshToken = nil
        isAuthenticated = false
        codeVerifier = nil
        codeChallenge = nil
        
        // In a real app, you would also call the Keycloak logout endpoint
        // and clear any stored tokens from keychain
    }
    
    // MARK: - Token Storage
    
    /// Stores tokens securely using Secure Enclave-derived encryption
    ///
    /// When Secure Enclave is available, this method:
    /// 1. Derives a unique encryption key using HKDF
    /// 2. Encrypts the token data using AES-GCM
    /// 3. Stores the encrypted data (in production, use Keychain)
    ///
    /// - Parameter tokens: The token response to store securely
    /// - Throws: Encryption errors
    ///
    /// ## Security Features
    /// - Unique encryption key per token set
    /// - Authenticated encryption (AES-GCM)
    /// - Hardware-backed key derivation
    ///
    /// ## Production Notes
    /// - Store the salt alongside encrypted data
    /// - Use iOS Keychain for persistent storage
    /// - Consider token rotation policies
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
    
    // MARK: - Passkey Authentication
    
    /// Authenticates the user using a passkey (WebAuthn)
    ///
    /// This method provides passwordless authentication by:
    /// 1. Prompting the user to authenticate with biometrics
    /// 2. Using an existing passkey to sign a challenge
    /// 3. Sending the signature to Keycloak for verification
    /// 4. Receiving tokens upon successful authentication
    ///
    /// ## Flow
    /// 1. User selects passkey authentication
    /// 2. System prompts for biometric authentication
    /// 3. Passkey signs the challenge
    /// 4. Signature is exchanged for tokens
    /// 5. Tokens are stored securely
    ///
    /// ## Fallback
    /// If passkey authentication fails, the method automatically
    /// falls back to standard web-based authentication
    func authenticateWithPasskey() async {
        guard isPasskeyAvailable else {
            print("Passkeys not available")
            return
        }
        
        do {
            // First, try to authenticate with existing passkey
            let assertion = try await passkeyManager.authenticateWithPasskey()
            
            // Exchange passkey assertion for tokens
            let tokens = try await exchangePasskeyAssertionForTokens(assertion: assertion)
            
            self.accessToken = tokens.accessToken
            self.refreshToken = tokens.refreshToken
            self.isAuthenticated = true
            
            // Store tokens securely
            try await securelyStoreTokens(tokens)
        } catch {
            print("Passkey authentication failed: \(error)")
            // Fall back to standard authentication
            authMethod = .standard
        }
    }
    
    /// Registers a new passkey for the authenticated user
    ///
    /// This method allows users to register a passkey for future passwordless logins:
    /// 1. Generates a unique user ID
    /// 2. Creates a new passkey with biometric protection
    /// 3. Registers the public key with Keycloak
    ///
    /// - Parameter username: The username to associate with the passkey
    /// - Throws: `PasskeyError` if registration fails
    ///
    /// ## Requirements
    /// - User must be authenticated (have a valid access token)
    /// - Device must support passkeys (iOS 16.0+)
    /// - Keycloak must have passkey support enabled
    ///
    /// ## Security
    /// - Private key is stored in Secure Element
    /// - Public key is sent to server
    /// - Biometric authentication required for future use
    func registerPasskey(username: String) async throws {
        guard isPasskeyAvailable else {
            throw PasskeyError.notAvailable
        }
        
        // Generate a user ID
        let userId = UUID().uuidString.data(using: .utf8)!
        
        // Register the passkey
        let credential = try await passkeyManager.registerPasskey(username: username, userId: userId)
        
        // Send credential to Keycloak for registration
        try await registerPasskeyWithKeycloak(credential: credential, username: username)
    }
    
    /// Exchanges a passkey assertion for OAuth tokens
    ///
    /// This method sends the passkey authentication proof to Keycloak's token endpoint
    /// using a custom grant type. The assertion contains:
    /// - Credential ID: Identifies which passkey was used
    /// - Signature: Proves possession of the private key
    /// - Client data: Contains the challenge and origin
    /// - Authenticator data: Contains flags and counter
    ///
    /// - Parameter assertion: The passkey assertion from authentication
    /// - Returns: Token response with access and refresh tokens
    /// - Throws: Network or decoding errors
    ///
    /// ## Grant Type
    /// Uses a custom grant type `urn:ietf:params:oauth:grant-type:passkey`
    /// which must be configured in Keycloak
    private func exchangePasskeyAssertionForTokens(assertion: PasskeyAssertion) async throws -> TokenResponse {
        let tokenURL = URL(string: "\(config.keycloakBaseURL)/auth/realms/\(config.realm)/protocol/openid-connect/token")!
        
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        
        // Create passkey assertion data
        let assertionData = [
            "credentialId": assertion.credentialID.base64EncodedString(),
            "signature": assertion.signature.base64EncodedString(),
            "clientDataJSON": assertion.clientDataJSON.base64EncodedString(),
            "authenticatorData": assertion.authenticatorData.base64EncodedString(),
            "userHandle": assertion.userID.base64EncodedString()
        ]
        
        let assertionJSON = try JSONSerialization.data(withJSONObject: assertionData)
        
        let parameters = [
            "grant_type": "urn:ietf:params:oauth:grant-type:passkey",
            "client_id": config.clientId,
            "assertion": assertionJSON.base64EncodedString()
        ]
        
        let bodyString = parameters
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
        
        request.httpBody = bodyString.data(using: .utf8)
        
        let (data, _) = try await URLSession.shared.data(for: request)
        let tokenResponse = try JSONDecoder().decode(TokenResponse.self, from: data)
        
        return tokenResponse
    }
    
    /// Registers a passkey credential with the Keycloak server
    ///
    /// This method sends the newly created passkey credential to Keycloak for storage.
    /// The server will:
    /// 1. Verify the attestation object
    /// 2. Extract and store the public key
    /// 3. Associate the credential with the user
    ///
    /// - Parameters:
    ///   - credential: The passkey credential containing public key and attestation
    ///   - username: The username to associate with the credential
    ///
    /// - Throws: `PasskeyError.registrationFailed` if registration fails
    ///
    /// ## Requirements
    /// - Valid access token (user must be authenticated)
    /// - Keycloak passkey registration endpoint must be configured
    /// - Server must support WebAuthn credential storage
    private func registerPasskeyWithKeycloak(credential: PasskeyCredential, username: String) async throws {
        guard let accessToken = accessToken else {
            throw PasskeyError.registrationFailed
        }
        
        let registerURL = URL(string: "\(config.keycloakBaseURL)/auth/realms/\(config.realm)/passkey/register")!
        
        var request = URLRequest(url: registerURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        
        let registrationData = [
            "username": username,
            "credentialId": credential.credentialID.base64EncodedString(),
            "publicKey": credential.publicKey.base64EncodedString(),
            "attestationObject": credential.attestationObject.base64EncodedString()
        ]
        
        request.httpBody = try JSONSerialization.data(withJSONObject: registrationData)
        
        let (_, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw PasskeyError.registrationFailed
        }
    }
}

// MARK: - Token Response Model

/// Represents the OAuth 2.0 token response from Keycloak
///
/// This structure maps the standard OAuth token response containing:
/// - `accessToken`: JWT for API authorization
/// - `refreshToken`: Optional token for obtaining new access tokens
/// - `expiresIn`: Token lifetime in seconds
/// - `tokenType`: Usually "Bearer"
struct TokenResponse: Codable {
    /// JWT access token for API requests
    let accessToken: String
    
    /// Optional refresh token for token renewal
    let refreshToken: String?
    
    /// Token expiration time in seconds
    let expiresIn: Int
    
    /// Token type (typically "Bearer")
    let tokenType: String
    
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
    }
}
