import SwiftUI
import WebKit

struct KeycloakWebView: UIViewRepresentable {
    @EnvironmentObject var authManager: KeycloakAuthManager
    @Environment(\.dismiss) var dismiss
    
    func makeUIView(context: Context) -> WKWebView {
        let webView = WKWebView()
        webView.navigationDelegate = context.coordinator
        return webView
    }
    
    func updateUIView(_ webView: WKWebView, context: Context) {
        if let authURL = authManager.getAuthorizationURL() {
            let request = URLRequest(url: authURL)
            webView.load(request)
        }
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    class Coordinator: NSObject, WKNavigationDelegate {
        var parent: KeycloakWebView
        
        init(_ parent: KeycloakWebView) {
            self.parent = parent
        }
        
        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let url = navigationAction.request.url else {
                decisionHandler(.allow)
                return
            }
            
            // Check if this is the redirect URL with authorization code
            if url.absoluteString.starts(with: parent.authManager.config.redirectURI) {
                if let code = extractAuthorizationCode(from: url) {
                    Task {
                        await parent.authManager.handleAuthorizationCode(code)
                        await MainActor.run {
                            parent.dismiss()
                        }
                    }
                    decisionHandler(.cancel)
                    return
                }
            }
            
            decisionHandler(.allow)
        }
        
        private func extractAuthorizationCode(from url: URL) -> String? {
            guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let queryItems = components.queryItems else {
                return nil
            }
            
            return queryItems.first(where: { $0.name == "code" })?.value
        }
    }
}
