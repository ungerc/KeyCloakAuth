import SwiftUI

@main
struct KeycloakAuthApp: App {
    @StateObject private var authManager = KeycloakAuthManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(authManager)
        }
    }
}
