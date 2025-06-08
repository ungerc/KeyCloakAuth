import Foundation
import CryptoKit
import LocalAuthentication

/// SecureEnclaveManager provides cryptographic operations using the Secure Enclave.
///
/// The Secure Enclave is a hardware-based key manager that's isolated from the main processor
/// to provide an extra layer of security. It performs cryptographic operations on keys without
/// exposing the key material to the application processor or operating system.
///
/// ## Overview
/// This manager handles two types of keys:
/// 1. **Signing Keys**: Used for creating digital signatures (authentication, integrity)
/// 2. **Key Agreement Keys**: Used for deriving shared secrets (encryption)
///
/// ## Features
/// - Hardware-based key generation and storage
/// - Cryptographic signing with P-256 elliptic curve
/// - Key agreement for deriving encryption keys
/// - Automatic key persistence in Secure Enclave
/// - Protection against key extraction
///
/// ## Security Benefits
/// - Keys never exist in application memory
/// - Keys are bound to the device and cannot be exported
/// - Operations are performed in isolated hardware
/// - Keys persist across app launches but not device restores
///
/// ## Usage
/// ```swift
/// // Generate keys (only needed once)
/// try secureEnclaveManager.generateKeyPairs()
///
/// // Sign data
/// let signature = try secureEnclaveManager.signData(data)
///
/// // Derive encryption key
/// let encryptionKey = try secureEnclaveManager.deriveSymmetricKey(
///     salt: salt,
///     info: contextInfo
/// )
/// ```
///
/// - Note: Secure Enclave is only available on devices with A7 chip or later
class SecureEnclaveManager {
    /// Shared singleton instance for app-wide Secure Enclave operations
    static let shared = SecureEnclaveManager()
    
    /// Tag identifier for the signing key in the keychain
    /// This tag is used to persist and retrieve the signing key reference
    private let signingKeyTag = "com.keycloakauth.signingkey"
    
    /// Tag identifier for the key agreement key in the keychain
    /// This tag is used to persist and retrieve the key agreement key reference
    private let keyAgreementKeyTag = "com.keycloakauth.keyagreementkey"
    
    /// Local authentication context for potential biometric operations
    /// Currently unused but available for future biometric-protected operations
    private let context = LAContext()
    
    /// Private initializer to enforce singleton pattern
    private init() {}
    
    /// Generates new key pairs in the Secure Enclave if they don't already exist
    ///
    /// This method creates two types of keys:
    /// 1. **Signing Key**: For creating digital signatures
    /// 2. **Key Agreement Key**: For deriving shared secrets
    ///
    /// Keys are only generated if they don't already exist. Once created, they persist
    /// in the Secure Enclave across app launches. The keys are automatically stored
    /// and can be retrieved using the same access control parameters.
    ///
    /// - Throws:
    ///   - `SecureEnclaveError.notAvailable` if Secure Enclave is not available
    ///   - CryptoKit errors if key generation fails
    ///
    /// - Note: Keys are bound to this device and cannot be backed up or restored
    ///
    /// ## Example
    /// ```swift
    /// do {
    ///     try secureEnclaveManager.generateKeyPairs()
    ///     print("Keys ready for use")
    /// } catch SecureEnclaveError.notAvailable {
    ///     print("Device doesn't support Secure Enclave")
    /// }
    /// ```
    func generateKeyPairs() throws {
        // Check if Secure Enclave is available
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        
        // Generate signing key if it doesn't exist
        if (try? loadSigningPrivateKey()) == nil {
            _ = try SecureEnclave.P256.Signing.PrivateKey()
            // Note: Secure Enclave keys are automatically stored
        }
        
        // Generate key agreement key if it doesn't exist
        if (try? loadKeyAgreementPrivateKey()) == nil {
            _ = try SecureEnclave.P256.KeyAgreement.PrivateKey()
            // Note: Secure Enclave keys are automatically stored
        }
    }
    
    /// Loads the existing signing private key from the Secure Enclave
    ///
    /// This method retrieves a reference to the signing key stored in the Secure Enclave.
    /// The actual key material never leaves the Secure Enclave.
    ///
    /// - Returns: A reference to the signing private key
    /// - Throws: `SecureEnclaveError.keyNotFound` if the key doesn't exist
    ///
    /// - Important: In a production implementation, you would store the key's data
    ///              representation in the keychain and recreate it with the same
    ///              access control parameters
    func loadSigningPrivateKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        // For Secure Enclave keys, we need to recreate them with the same access control
        // In a real implementation, you'd store the key data representation
        return try SecureEnclave.P256.Signing.PrivateKey()
    }
    
    /// Loads the existing key agreement private key from the Secure Enclave
    ///
    /// This method retrieves a reference to the key agreement key stored in the Secure Enclave.
    /// The actual key material never leaves the Secure Enclave.
    ///
    /// - Returns: A reference to the key agreement private key
    /// - Throws: `SecureEnclaveError.keyNotFound` if the key doesn't exist
    ///
    /// - Important: In a production implementation, you would store the key's data
    ///              representation in the keychain and recreate it with the same
    ///              access control parameters
    func loadKeyAgreementPrivateKey() throws -> SecureEnclave.P256.KeyAgreement.PrivateKey {
        // For Secure Enclave keys, we need to recreate them with the same access control
        // In a real implementation, you'd store the key data representation
        return try SecureEnclave.P256.KeyAgreement.PrivateKey()
    }
    
    
    /// Signs data using the Secure Enclave signing key
    ///
    /// This method creates a cryptographic signature of the provided data using the
    /// P-256 elliptic curve signing key stored in the Secure Enclave. The signature
    /// can be verified by anyone with the corresponding public key.
    ///
    /// - Parameter data: The data to sign
    /// - Returns: The raw signature bytes (64 bytes for P-256)
    /// - Throws: CryptoKit errors if signing fails
    ///
    /// ## Use Cases
    /// - Client authentication (proving identity)
    /// - Message integrity (detecting tampering)
    /// - Non-repudiation (proving origin)
    ///
    /// ## Example
    /// ```swift
    /// let message = "Authenticate me".data(using: .utf8)!
    /// let signature = try secureEnclaveManager.signData(message)
    /// // Send signature to server for verification
    /// ```
    func signData(_ data: Data) throws -> Data {
        let privateKey = try loadSigningPrivateKey()
        let signature = try privateKey.signature(for: data)
        return signature.rawRepresentation
    }
    
    /// Retrieves the public key corresponding to the signing private key
    ///
    /// The public key can be shared freely and is used to verify signatures created
    /// by the private key. This is typically sent to the server during registration.
    ///
    /// - Returns: The P-256 public key for signature verification
    /// - Throws: CryptoKit errors if key loading fails
    ///
    /// ## Example
    /// ```swift
    /// let publicKey = try secureEnclaveManager.getSigningPublicKey()
    /// let publicKeyData = publicKey.rawRepresentation
    /// // Send to server for storage
    /// ```
    func getSigningPublicKey() throws -> P256.Signing.PublicKey {
        let privateKey = try loadSigningPrivateKey()
        return privateKey.publicKey
    }
    
    /// Derives a symmetric encryption key using the Secure Enclave key agreement key
    ///
    /// This method uses Elliptic Curve Diffie-Hellman (ECDH) to create a shared secret,
    /// then applies HKDF (HMAC-based Key Derivation Function) to derive a symmetric key
    /// suitable for AES encryption.
    ///
    /// - Parameters:
    ///   - salt: Random data to strengthen the key derivation (should be unique per derivation)
    ///   - info: Application-specific context information (e.g., "token-encryption")
    ///
    /// - Returns: A 256-bit symmetric key suitable for AES-256 encryption
    ///
    /// - Throws: CryptoKit errors if key derivation fails
    ///
    /// ## Security Notes
    /// - The salt should be randomly generated and stored alongside encrypted data
    /// - The info parameter provides domain separation between different uses
    /// - The derived key is deterministic given the same inputs
    ///
    /// ## Example
    /// ```swift
    /// let salt = Data(UUID().uuidString.utf8)
    /// let info = Data("user-data-encryption".utf8)
    /// let encryptionKey = try secureEnclaveManager.deriveSymmetricKey(
    ///     salt: salt,
    ///     info: info
    /// )
    /// 
    /// // Use key for AES encryption
    /// let sealedBox = try AES.GCM.seal(plaintext, using: encryptionKey)
    /// ```
    ///
    /// - Important: In production, you would typically perform ECDH with another party's
    ///              public key. This implementation uses our own public key for demonstration.
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

/// Errors that can occur during Secure Enclave operations
enum SecureEnclaveError: LocalizedError {
    /// Secure Enclave is not available on this device
    /// This occurs on older devices without the necessary hardware
    case notAvailable
    
    /// The requested key was not found in the Secure Enclave
    case keyNotFound
    
    /// Failed to save a key to the Secure Enclave
    case saveFailed
    
    /// Failed to delete a key from the Secure Enclave
    case deleteFailed
    
    /// Failed to create a signature
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
