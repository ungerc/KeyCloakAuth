import SwiftUI

@main
struct KeycloakAuthApp: App {
    @State private var config = KeycloakConfig()
    @State private var authManager: KeycloakAuthManager

    init() {
        let config = KeycloakConfig()
        self._config = State(initialValue: config)
        self._authManager = State(initialValue: KeycloakAuthManager(config: config))
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(authManager)
        }
    }
}
