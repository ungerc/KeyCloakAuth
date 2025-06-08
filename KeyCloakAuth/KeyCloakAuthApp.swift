import SwiftUI

@main
struct KeycloakAuthApp: App {
    @State private var authManager = KeycloakAuthManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(authManager)
        }
    }
}
