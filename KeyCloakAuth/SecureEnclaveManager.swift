import Foundation
import CryptoKit
import LocalAuthentication

class SecureEnclaveManager {
    static let shared = SecureEnclaveManager()
    
    private let keyTag = "com.keycloakauth.securekey"
    private let context = LAContext()
    
    private init() {}
    
    /// Generate a new key pair in the Secure Enclave
    func generateKeyPair() throws -> SecureEnclave.P256.Signing.PrivateKey {
        // Check if Secure Enclave is available
        guard SecureEnclave.isAvailable else {
            throw SecureEnclaveError.notAvailable
        }
        
        // Try to load existing key first
        if let existingKey = try? loadPrivateKey() {
            return existingKey
        }
        
        // Generate new key
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
        
        // Store key reference
        try savePrivateKey(privateKey)
        
        return privateKey
    }
    
    /// Load existing private key from Secure Enclave
    func loadPrivateKey() throws -> SecureEnclave.P256.Signing.PrivateKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrLabel as String: keyTag,
            kSecReturnRef as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError.keyNotFound
        }
        
        let key = item as! SecKey
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: key as! Data)
    }
    
    /// Save private key reference
    private func savePrivateKey(_ privateKey: SecureEnclave.P256.Signing.PrivateKey) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrLabel as String: keyTag,
            kSecValueRef as String: privateKey
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw SecureEnclaveError.saveFailed
        }
    }
    
    /// Delete stored key
    func deleteKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrLabel as String: keyTag
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SecureEnclaveError.deleteFailed
        }
    }
    
    /// Sign data with the private key
    func signData(_ data: Data) throws -> Data {
        let privateKey = try loadPrivateKey()
        let signature = try privateKey.signature(for: data)
        return signature.rawRepresentation
    }
    
    /// Get public key for verification
    func getPublicKey() throws -> P256.Signing.PublicKey {
        let privateKey = try loadPrivateKey()
        return privateKey.publicKey
    }
    
    /// Create a derived key from the Secure Enclave key for encryption
    func deriveSymmetricKey(salt: Data, info: Data) throws -> SymmetricKey {
        let privateKey = try loadPrivateKey()
        
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
