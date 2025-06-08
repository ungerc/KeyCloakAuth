import Foundation
import AuthenticationServices
import CryptoKit

@MainActor
class PasskeyManager: NSObject {
    static let shared = PasskeyManager()
    
    var isPasskeyAvailable = false
    private let domain: String
    
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
    
    private func checkPasskeyAvailability() {
        if #available(iOS 16.0, *) {
            isPasskeyAvailable = true
        } else {
            isPasskeyAvailable = false
        }
    }
    
    /// Register a new passkey
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
    
    /// Authenticate with an existing passkey
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
    
    /// Generate a cryptographic challenge
    private func generateChallenge() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }
    
    // Continuations for async/await
    private var registrationContinuation: CheckedContinuation<PasskeyCredential, Error>?
    private var assertionContinuation: CheckedContinuation<PasskeyAssertion, Error>?
}

// MARK: - ASAuthorizationControllerDelegate
extension PasskeyManager: ASAuthorizationControllerDelegate {
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        if #available(iOS 16.0, *) {
            if let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
                let passkeyCredential = PasskeyCredential(
                    credentialID: credential.credentialID,
                    publicKey: credential.rawClientDataJSON,
                    attestationObject: credential.rawAttestationObject ?? Data()
                )
                registrationContinuation?.resume(returning: passkeyCredential)
                registrationContinuation = nil
            } else if let assertion = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
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
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        registrationContinuation?.resume(throwing: error)
        registrationContinuation = nil
        assertionContinuation?.resume(throwing: error)
        assertionContinuation = nil
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding
extension PasskeyManager: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first else {
            fatalError("No window found")
        }
        return window
    }
}

// MARK: - Data Models
struct PasskeyCredential {
    let credentialID: Data
    let publicKey: Data
    let attestationObject: Data
}

struct PasskeyAssertion {
    let credentialID: Data
    let signature: Data
    let userID: Data
    let clientDataJSON: Data
    let authenticatorData: Data
}

enum PasskeyError: LocalizedError {
    case notAvailable
    case registrationFailed
    case authenticationFailed
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
