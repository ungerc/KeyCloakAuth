import SwiftUI

struct ContentView: View {
    @Environment(KeycloakAuthManager.self) private var authManager

    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                if authManager.isAuthenticated {
                    AuthenticatedView()
                } else {
                    LoginView()
                }
            }
            .navigationTitle("Keycloak Auth Demo")
        }
    }
}

struct LoginView: View {
    @Environment(KeycloakAuthManager.self) private var authManager

    @State private var showingWebView = false
    @State private var showingAuthOptions = false
    @State private var isAuthenticating = false

    var body: some View {
        VStack(spacing: 20) {
            Text("Welcome to Keycloak Auth Demo")
                .font(.title2)
                .padding()
            
            if authManager.isSecureEnclaveAvailable {
                Text("Secure Enclave: ✅")
                    .font(.caption)
                    .foregroundColor(.green)
            }
            
            if authManager.isPasskeyAvailable {
                Text("Passkeys: ✅")
                    .font(.caption)
                    .foregroundColor(.green)
            }

            Button("Login with Keycloak") {
                showingAuthOptions = true
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(isAuthenticating)
            
            if isAuthenticating {
                ProgressView()
                    .progressViewStyle(CircularProgressViewStyle())
            }
        }
        .confirmationDialog("Choose Authentication Method", isPresented: $showingAuthOptions) {
            Button("Standard Login") {
                authManager.authMethod = .standard
                showingWebView = true
            }
            
            if authManager.isSecureEnclaveAvailable {
                Button("Login with Secure Enclave") {
                    authManager.authMethod = .secureEnclave
                    showingWebView = true
                }
            }
            
            if authManager.isPasskeyAvailable {
                Button("Login with Passkey") {
                    authManager.authMethod = .passkey
                    Task {
                        isAuthenticating = true
                        await authManager.authenticateWithPasskey()
                        isAuthenticating = false
                        
                        // If passkey auth failed, fall back to web view
                        if !authManager.isAuthenticated && authManager.authMethod == .standard {
                            showingWebView = true
                        }
                    }
                }
            }
            
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Select how you'd like to authenticate")
        }
        .sheet(isPresented: $showingWebView) {
            KeycloakWebView()
        }
    }
}

struct AuthenticatedView: View {
    @Environment(KeycloakAuthManager.self) private var authManager
    @State private var showingPasskeyRegistration = false
    @State private var username = ""
    @State private var registrationError: String?

    var body: some View {
        VStack(spacing: 20) {
            Text("Successfully Authenticated!")
                .font(.title2)
                .foregroundColor(.green)
            
            HStack {
                Text("Auth Method:")
                    .font(.caption)
                Text(authMethodDescription)
                    .font(.caption)
                    .bold()
            }

            if let token = authManager.accessToken {
                Text("Access Token (truncated):")
                    .font(.headline)
                Text(String(token.prefix(50)) + "...")
                    .font(.system(.caption, design: .monospaced))
                    .padding()
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(8)
            }
            
            if authManager.isPasskeyAvailable && authManager.authMethod != .passkey {
                Button("Register Passkey") {
                    showingPasskeyRegistration = true
                }
                .buttonStyle(.bordered)
            }

            Button("Logout") {
                authManager.logout()
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
        }
        .padding()
        .alert("Register Passkey", isPresented: $showingPasskeyRegistration) {
            TextField("Username", text: $username)
            Button("Register") {
                Task {
                    do {
                        try await authManager.registerPasskey(username: username)
                        username = ""
                    } catch {
                        registrationError = error.localizedDescription
                    }
                }
            }
            Button("Cancel", role: .cancel) {
                username = ""
            }
        } message: {
            Text("Enter your username to register a passkey for faster login next time")
        }
        .alert("Registration Error", isPresented: .constant(registrationError != nil)) {
            Button("OK") {
                registrationError = nil
            }
        } message: {
            if let error = registrationError {
                Text(error)
            }
        }
    }
    
    private var authMethodDescription: String {
        switch authManager.authMethod {
        case .standard:
            return "Standard"
        case .secureEnclave:
            return "Secure Enclave Enhanced"
        case .passkey:
            return "Passkey"
        }
    }
}

#Preview {
    ContentView()
        .environment(KeycloakAuthManager())
}
