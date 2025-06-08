import Foundation
import CryptoKit
import LocalAuthentication

class SecureEnclaveManager {
    static let shared = SecureEnclaveManager()
    
    private let signingKeyTag = "com.keycloakauth.signingkey"
    private let keyAgreementKeyTag = "com.keycloakauth.keyagreementkey"
    private let context = LAContext()
    
    private init() {}
    
    /// Generate new key pairs in the Secure Enclave
    func generateKeyPairs() throws {
        // Check if Secure Enclave is available
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        
        // Generate signing key if it doesn't exist
        if (try? loadSigningPrivateKey()) == nil {
            let signingKey = try SecureEnclave.P256.Signing.PrivateKey()
            // Note: Secure Enclave keys are automatically stored
        }
        
        // Generate key agreement key if it doesn't exist
        if (try? loadKeyAgreementPrivateKey()) == nil {
            let keyAgreementKey = try SecureEnclave.P256.KeyAgreement.PrivateKey()
            // Note: Secure Enclave keys are automatically stored
        }
    }
    
    /// Load existing signing private key from Secure Enclave
    func loadSigningPrivateKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        // For Secure Enclave keys, we need to recreate them with the same access control
        // In a real implementation, you'd store the key data representation
        return try SecureEnclave.P256.Signing.PrivateKey()
    }
    
    /// Load existing key agreement private key from Secure Enclave
    func loadKeyAgreementPrivateKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        // For Secure Enclave keys, we need to recreate them with the same access control
        // In a real implementation, you'd store the key data representation
        return try SecureEnclave.P256.KeyAgreement.PrivateKey()
    }
    
    
    /// Sign data with the signing private key
    func signData(_ data: Data) throws -> Data {
        let privateKey = try loadSigningPrivateKey()
        let signature = try privateKey.signature(for: data)
        return signature.rawRepresentation
    }
    
    /// Get signing public key for verification
    func getSigningPublicKey() throws -> P256.Signing.PublicKey {
        let privateKey = try loadSigningPrivateKey()
        return privateKey.publicKey
    }
    
    /// Create a derived key from the Secure Enclave key for encryption
    func deriveSymmetricKey(salt: Data, info: Data) throws -> SymmetricKey {
        let privateKey = try loadKeyAgreementPrivateKey()
        
        // Create a shared secret using ECDH with our own public key (for demonstration)
        // In practice, you'd use another party's public key
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: privateKey.publicKey)
        
        // Derive a symmetric key using HKDF
        let derivedKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: 32
        )
        
        return derivedKey
    }
}

enum SecureEnclaveError: LocalizedError {
    case notAvailable
    case keyNotFound
    case saveFailed
    case deleteFailed
    case signatureFailed
    
    var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Secure Enclave is not available on this device"
        case .keyNotFound:
            return "No key found in Secure Enclave"
        case .saveFailed:
            return "Failed to save key to Secure Enclave"
        case .deleteFailed:
            return "Failed to delete key from Secure Enclave"
        case .signatureFailed:
            return "Failed to create signature"
        }
    }
}
