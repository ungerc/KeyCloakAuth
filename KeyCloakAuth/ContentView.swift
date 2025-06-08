import SwiftUI

struct ContentView: View {
    @EnvironmentObject var authManager: KeycloakAuthManager

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
    @EnvironmentObject var authManager: KeycloakAuthManager
    @State private var showingWebView = false

    var body: some View {
        VStack(spacing: 20) {
            Text("Welcome to Keycloak Auth Demo")
                .font(.title2)
                .padding()

            Button("Login with Keycloak") {
                showingWebView = true
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .sheet(isPresented: $showingWebView) {
            KeycloakWebView()
        }
    }
}

struct AuthenticatedView: View {
    @EnvironmentObject var authManager: KeycloakAuthManager

    var body: some View {
        VStack(spacing: 20) {
            Text("Successfully Authenticated!")
                .font(.title2)
                .foregroundColor(.green)

            if let token = authManager.accessToken {
                Text("Access Token (truncated):")
                    .font(.headline)
                Text(String(token.prefix(50)) + "...")
                    .font(.system(.caption, design: .monospaced))
                    .padding()
                    .background(Color.gray.opacity(0.1))
                    .cornerRadius(8)
            }

            Button("Logout") {
                authManager.logout()
            }
            .buttonStyle(.bordered)
            .controlSize(.large)
        }
        .padding()
    }
}

#Preview {
    ContentView()
        .environmentObject(KeycloakAuthManager())
}
