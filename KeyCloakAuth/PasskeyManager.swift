import Foundation
import AuthenticationServices
import CryptoKit

/// PasskeyManager handles WebAuthn-based passkey authentication for Keycloak.
///
/// This manager provides a modern, passwordless authentication experience using
/// platform authenticators (Face ID, Touch ID) through Apple's Authentication Services framework.
/// It implements the WebAuthn standard for creating and using passkeys.
///
/// ## Overview
/// Passkeys are cryptographic key pairs where:
/// - The private key is stored securely in the device's Secure Element
/// - The public key is registered with the Keycloak server
/// - Authentication happens through cryptographic signatures without transmitting passwords
///
/// ## Features
/// - Automatic availability detection for iOS 16.0+
/// - Passkey registration for new credentials
/// - Passkey authentication for existing credentials
/// - Secure challenge generation
/// - Async/await support for modern Swift concurrency
///
/// ## Usage
/// ```swift
/// // Check availability
/// if passkeyManager.isPasskeyAvailable {
///     // Register a new passkey
///     let credential = try await passkeyManager.registerPasskey(
///         username: "user@example.com",
///         userId: userData
///     )
///
///     // Authenticate with existing passkey
///     let assertion = try await passkeyManager.authenticateWithPasskey()
/// }
/// ```
///
/// ## Security Considerations
/// - Passkeys are bound to the domain specified in the relying party identifier
/// - User verification (biometric or passcode) is preferred for all operations
/// - Challenges are generated using secure random bytes
/// - All operations require user interaction and consent
///
/// - Note: This class inherits from NSObject to conform to ASAuthorizationControllerDelegate
@MainActor
class PasskeyManager: NSObject {
    /// Shared singleton instance for app-wide passkey management
    static let shared = PasskeyManager()
    
    /// Indicates whether passkeys are available on the current device
    /// - Note: Requires iOS 16.0 or later
    var isPasskeyAvailable = false
    
    /// The relying party identifier (domain) for WebAuthn operations
    /// This should match your Keycloak server's domain
    private let domain: String
    
    /// Initializes the PasskeyManager and configures the relying party domain
    ///
    /// The domain is extracted from the Keycloak configuration and used as the
    /// relying party identifier for all WebAuthn operations. This ensures passkeys
    /// are bound to your specific Keycloak instance.
    override init() {
        // Extract domain from Keycloak config
        let config = KeycloakConfig()
        if let url = URL(string: config.keycloakBaseURL),
           let host = url.host {
            self.domain = host
        } else {
            self.domain = "keycloak.local"
        }
        
        super.init()
        checkPasskeyAvailability()
    }
    
    /// Checks if passkeys are available on the current device
    ///
    /// Passkeys require iOS 16.0 or later. This method sets the `isPasskeyAvailable`
    /// property based on the iOS version.
    private func checkPasskeyAvailability() {
        if #available(iOS 16.0, *) {
            isPasskeyAvailable = true
        } else {
            isPasskeyAvailable = false
        }
    }
    
    /// Registers a new passkey credential for the specified user
    ///
    /// This method initiates the WebAuthn registration ceremony, which:
    /// 1. Generates a cryptographic challenge
    /// 2. Prompts the user to authenticate with biometrics or passcode
    /// 3. Creates a new key pair in the device's Secure Element
    /// 4. Returns the public key and attestation data
    ///
    /// - Parameters:
    ///   - username: The username to associate with the passkey (e.g., email address)
    ///   - userId: A unique identifier for the user (should be opaque and not contain PII)
    ///
    /// - Returns: A `PasskeyCredential` containing the credential ID, public key, and attestation
    ///
    /// - Throws:
    ///   - `PasskeyError.notAvailable` if iOS version is below 16.0
    ///   - Authentication Services errors if the user cancels or biometric authentication fails
    ///
    /// - Note: The returned credential should be sent to your Keycloak server for storage
    ///
    /// ## Example
    /// ```swift
    /// do {
    ///     let userId = UUID().uuidString.data(using: .utf8)!
    ///     let credential = try await passkeyManager.registerPasskey(
    ///         username: "user@example.com",
    ///         userId: userId
    ///     )
    ///     // Send credential to server for registration
    /// } catch {
    ///     print("Passkey registration failed: \(error)")
    /// }
    /// ```
    func registerPasskey(username: String, userId: Data) async throws -> PasskeyCredential {
        guard #available(iOS 16.0, *) else {
            throw PasskeyError.notAvailable
        }
        
        let challenge = generateChallenge()
        
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        
        let registrationRequest = platformProvider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: username,
            userID: userId
        )
        
        // Configure the request
        registrationRequest.displayName = username
        registrationRequest.userVerificationPreference = .preferred
        
        let authController = ASAuthorizationController(authorizationRequests: [registrationRequest])
        authController.delegate = self
        authController.presentationContextProvider = self
        
        return try await withCheckedThrowingContinuation { continuation in
            self.registrationContinuation = continuation
            authController.performRequests()
        }
    }
    
    /// Authenticates the user with an existing passkey
    ///
    /// This method initiates the WebAuthn authentication ceremony, which:
    /// 1. Generates a cryptographic challenge
    /// 2. Prompts the user to select a passkey (if multiple exist)
    /// 3. Requests biometric or passcode authentication
    /// 4. Signs the challenge with the private key
    /// 5. Returns the signature and authentication data
    ///
    /// - Returns: A `PasskeyAssertion` containing the signature and authentication data
    ///
    /// - Throws:
    ///   - `PasskeyError.notAvailable` if iOS version is below 16.0
    ///   - Authentication Services errors if the user cancels or biometric authentication fails
    ///   - Error if no passkeys are found for the domain
    ///
    /// - Note: The returned assertion should be sent to your Keycloak server for verification
    ///
    /// ## Example
    /// ```swift
    /// do {
    ///     let assertion = try await passkeyManager.authenticateWithPasskey()
    ///     // Send assertion to server for verification and token exchange
    /// } catch {
    ///     print("Passkey authentication failed: \(error)")
    /// }
    /// ```
    ///
    /// ## Security
    /// - The challenge prevents replay attacks
    /// - User verification ensures the authorized user is present
    /// - The signature proves possession of the private key without exposing it
    func authenticateWithPasskey() async throws -> PasskeyAssertion {
        guard #available(iOS 16.0, *) else {
            throw PasskeyError.notAvailable
        }
        
        let challenge = generateChallenge()
        
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: domain)
        
        let assertionRequest = platformProvider.createCredentialAssertionRequest(challenge: challenge)
        assertionRequest.userVerificationPreference = .preferred
        
        let authController = ASAuthorizationController(authorizationRequests: [assertionRequest])
        authController.delegate = self
        authController.presentationContextProvider = self
        
        return try await withCheckedThrowingContinuation { continuation in
            self.assertionContinuation = continuation
            authController.performRequests()
        }
    }
    
    /// Generates a cryptographically secure random challenge
    ///
    /// The challenge is used to prevent replay attacks in WebAuthn ceremonies.
    /// It should be:
    /// - At least 32 bytes long for security
    /// - Generated using a cryptographically secure random number generator
    /// - Unique for each authentication or registration attempt
    /// - Verified by the server to match what was sent
    ///
    /// - Returns: 32 bytes of cryptographically secure random data
    private func generateChallenge() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
    
    // MARK: - Async/Await Support
    
    /// Continuation for passkey registration operations
    /// Used to bridge the delegate-based ASAuthorizationController to async/await
    private var registrationContinuation: CheckedContinuation<PasskeyCredential, Error>?
    
    /// Continuation for passkey authentication operations
    /// Used to bridge the delegate-based ASAuthorizationController to async/await
    private var assertionContinuation: CheckedContinuation<PasskeyAssertion, Error>?
}

// MARK: - ASAuthorizationControllerDelegate

/// Handles the completion of passkey operations
extension PasskeyManager: ASAuthorizationControllerDelegate {
    /// Called when a passkey operation completes successfully
    ///
    /// This method handles two types of successful operations:
    /// 1. **Registration**: Creates a new passkey and returns the public key
    /// 2. **Authentication**: Uses an existing passkey to sign a challenge
    ///
    /// The method extracts the relevant data from the authorization result and
    /// resumes the appropriate continuation to return the data to the caller.
    ///
    /// - Parameters:
    ///   - controller: The authorization controller that completed
    ///   - authorization: The successful authorization result containing credential data
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if #available(iOS 16.0, *) {
            if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
                // Handle successful registration
                let passkeyCredential = PasskeyCredential(
                    credentialID: credential.credentialID,
                    publicKey: credential.rawClientDataJSON,
                    attestationObject: credential.rawAttestationObject ?? Data()
                )
                registrationContinuation?.resume(returning: passkeyCredential)
                registrationContinuation = nil
            } else if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
                // Handle successful authentication
                let passkeyAssertion = PasskeyAssertion(
                    credentialID: assertion.credentialID,
                    signature: assertion.signature,
                    userID: assertion.userID,
                    clientDataJSON: assertion.rawClientDataJSON,
                    authenticatorData: assertion.rawAuthenticatorData
                )
                assertionContinuation?.resume(returning: passkeyAssertion)
                assertionContinuation = nil
            }
        }
    }
    
    /// Called when a passkey operation fails or is cancelled
    ///
    /// Common error scenarios include:
    /// - User cancelled the operation
    /// - Biometric authentication failed
    /// - No passkeys found for the domain
    /// - Device doesn't support passkeys
    ///
    /// - Parameters:
    ///   - controller: The authorization controller that failed
    ///   - error: The error that occurred during the operation
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        registrationContinuation?.resume(throwing: error)
        registrationContinuation = nil
        assertionContinuation?.resume(throwing: error)
        assertionContinuation = nil
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding

/// Provides the presentation context for passkey UI
extension PasskeyManager: ASAuthorizationControllerPresentationContextProviding {
    /// Returns the window to present the passkey UI
    ///
    /// This method is required for the system to know where to present the
    /// passkey selection and biometric authentication UI. It returns the
    /// app's main window.
    ///
    /// - Parameter controller: The authorization controller requesting a presentation anchor
    /// - Returns: The window to present the passkey UI
    ///
    /// - Note: In a multi-window app, you might need more sophisticated logic
    ///         to determine the appropriate window
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first else {
            fatalError("No window found")
        }
        return window
    }
}

// MARK: - Data Models

/// Represents a newly created passkey credential
///
/// This structure contains all the data needed to register a passkey with your server:
/// - `credentialID`: Unique identifier for this credential
/// - `publicKey`: The public key to be stored on the server (in clientDataJSON format)
/// - `attestationObject`: Cryptographic proof of the authenticator's properties
struct PasskeyCredential {
    /// Unique identifier for this credential
    /// This ID is used to identify the credential in future authentication requests
    let credentialID: Data
    
    /// The client data JSON containing the public key and other metadata
    /// This should be verified and parsed on the server to extract the actual public key
    let publicKey: Data
    
    /// Attestation object containing authenticator data and attestation statement
    /// This proves the credential was created by a legitimate authenticator
    let attestationObject: Data
}

/// Represents an authentication assertion from an existing passkey
///
/// This structure contains the signature and data needed to verify authentication:
/// - `credentialID`: Identifies which credential was used
/// - `signature`: Cryptographic signature proving possession of the private key
/// - `userID`: The user handle associated with the credential
/// - `clientDataJSON`: Client data including the challenge
/// - `authenticatorData`: Data about the authenticator state
struct PasskeyAssertion {
    /// The ID of the credential used for authentication
    let credentialID: Data
    
    /// Cryptographic signature over the authenticator data and client data hash
    /// This proves the user possesses the private key
    let signature: Data
    
    /// The user handle provided during registration
    let userID: Data
    
    /// Client data JSON containing the challenge and other metadata
    let clientDataJSON: Data
    
    /// Authenticator data including flags and signature counter
    let authenticatorData: Data
}

/// Errors that can occur during passkey operations
enum PasskeyError: LocalizedError {
    /// Passkeys are not available (iOS < 16.0)
    case notAvailable
    
    /// Failed to register a new passkey
    case registrationFailed
    
    /// Failed to authenticate with an existing passkey
    case authenticationFailed
    
    /// Received an invalid or unexpected response
    case invalidResponse
    
    var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Passkeys are not available on this device"
        case .registrationFailed:
            return "Failed to register passkey"
        case .authenticationFailed:
            return "Failed to authenticate with passkey"
        case .invalidResponse:
            return "Invalid response from passkey operation"
        }
    }
}
