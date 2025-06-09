import SwiftUI

@main
struct KeycloakAuthApp: App {
    @State private var authManager: KeycloakAuthManager

    init() {
        let config = KeycloakConfig()
        self._authManager = State(initialValue: KeycloakAuthManager(config: config))
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(authManager)
        }
    }
}
