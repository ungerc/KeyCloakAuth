import SwiftUI

struct KeycloakConfigView: View {
    @Environment(\.dismiss) var dismiss
    @Bindable var config: KeycloakConfig
    @State private var showingResetConfirmation = false
    
    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Keycloak Server")) {
                    TextField("Base URL", text: $config.keycloakBaseURL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textContentType(.URL)
                    
                    TextField("Realm", text: $config.realm)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                
                Section(header: Text("Client Configuration")) {
                    TextField("Client ID", text: $config.clientId)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    
                    TextField("Redirect URI", text: $config.redirectURI)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textContentType(.URL)
                }
                
                Section(header: Text("Status")) {
                    HStack {
                        Text("Configuration Status:")
                        Spacer()
                        if config.isConfigured {
                            Label("Configured", systemImage: "checkmark.circle.fill")
                                .foregroundColor(.green)
                                .font(.caption)
                        } else {
                            Label("Not Configured", systemImage: "exclamationmark.circle.fill")
                                .foregroundColor(.orange)
                                .font(.caption)
                        }
                    }
                    
                    HStack {
                        Text("URL Scheme:")
                        Spacer()
                        Text(config.urlScheme)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }
                
                Section(footer: Text("Make sure your app's Info.plist includes the URL scheme '\(config.urlScheme)' to handle OAuth callbacks.")) {
                    EmptyView()
                }
                
                Section {
                    Button("Reset to Defaults") {
                        showingResetConfirmation = true
                    }
                    .foregroundColor(.red)
                }
            }
            .navigationTitle("Keycloak Configuration")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Done") {
                        dismiss()
                    }
                }
            }
        }
        .confirmationDialog("Reset Configuration?", isPresented: $showingResetConfirmation) {
            Button("Reset", role: .destructive) {
                config.reset()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This will reset all configuration values to their defaults.")
        }
    }
}

#Preview {
    KeycloakConfigView(config: KeycloakConfig())
}
