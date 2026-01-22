import Foundation
import AppleAPI
import Path

public class FastlaneSessionManager {

    public enum Constants {
        public static let fastlaneSessionEnvVarName = "FASTLANE_SESSION"
        public static let fastlaneSpaceshipDir = Path.environmentHome.url
                                                    .appendingPathComponent(".fastlane")
                                                    .appendingPathComponent("spaceship")
    }

    public init() {}

    public func setupFastlaneAuth(fastlaneUser: String) {
        Current.logging.log("🔐 [FASTLANE AUTH] Setting up fastlane authentication with user: \(fastlaneUser)")
        // Use ephemeral session so that cookies don't conflict with normal usage
        AppleAPI.Current.network.session = URLSession(configuration: .ephemeral)
        Current.logging.log("🔐 [FASTLANE AUTH] Created ephemeral URLSession")
        switch fastlaneUser {
        case Constants.fastlaneSessionEnvVarName:
            Current.logging.log("🔐 [FASTLANE AUTH] Importing cookies from environment variable")
            importFastlaneCookiesFromEnv()
        default:
            Current.logging.log("🔐 [FASTLANE AUTH] Importing cookies from file for user: \(fastlaneUser)")
            importFastlaneCookiesFromFile(fastlaneUser: fastlaneUser)
        }
    }

    private func importFastlaneCookiesFromEnv() {
        Current.logging.log("🔐 [FASTLANE AUTH] Checking for \(Constants.fastlaneSessionEnvVarName) environment variable")
        guard let cookieString = Current.shell.env(Constants.fastlaneSessionEnvVarName) else {
            Current.logging.log("❌ [FASTLANE AUTH] \(Constants.fastlaneSessionEnvVarName) not set".red)
            return
        }
        Current.logging.log("✅ [FASTLANE AUTH] Found \(Constants.fastlaneSessionEnvVarName), parsing cookies...")
        do {
            let cookies = try Current.fastlaneCookieParser.parse(cookieString: cookieString)
            Current.logging.log("✅ [FASTLANE AUTH] Successfully parsed \(cookies.count) cookies")
            cookies.forEach { cookie in
                Current.logging.log("🍪 [FASTLANE AUTH] Cookie: name=\(cookie.name), domain=\(cookie.domain), path=\(cookie.path), expires=\(String(describing: cookie.expiresDate))")
                AppleAPI.Current.network.session.configuration.httpCookieStorage!.setCookie(cookie)
            }
            Current.logging.log("✅ [FASTLANE AUTH] Cookies imported to URLSession")

            // Verify cookies were actually set
            if let storage = AppleAPI.Current.network.session.configuration.httpCookieStorage,
               let allCookies = storage.cookies {
                Current.logging.log("🍪 [FASTLANE AUTH] Total cookies in storage: \(allCookies.count)")
            }
        } catch {
            Current.logging.log("❌ [FASTLANE AUTH] Failed to parse cookies from \(Constants.fastlaneSessionEnvVarName): \(error)".red)
            return
        }
    }

    private func importFastlaneCookiesFromFile(fastlaneUser: String) {
        let cookieFilePath = Constants
                                .fastlaneSpaceshipDir
                                .appendingPathComponent(fastlaneUser)
                                .appendingPathComponent("cookie")
        Current.logging.log("🔐 [FASTLANE AUTH] Reading cookies from file: \(cookieFilePath)")
        guard
            let cookieString = try? String(contentsOf: cookieFilePath)
        else {
            Current.logging.log("❌ [FASTLANE AUTH] Could not read cookies from \(cookieFilePath)".red)
            return
        }
        Current.logging.log("✅ [FASTLANE AUTH] Successfully read cookie file, parsing cookies...")
        do {
            let cookies = try Current.fastlaneCookieParser.parse(cookieString: cookieString)
            Current.logging.log("✅ [FASTLANE AUTH] Successfully parsed \(cookies.count) cookies")
            cookies.forEach { cookie in
                Current.logging.log("🍪 [FASTLANE AUTH] Cookie: name=\(cookie.name), domain=\(cookie.domain), path=\(cookie.path), expires=\(String(describing: cookie.expiresDate))")
                AppleAPI.Current.network.session.configuration.httpCookieStorage!.setCookie(cookie)
            }
            Current.logging.log("✅ [FASTLANE AUTH] Cookies imported to URLSession")
        } catch {
            Current.logging.log("❌ [FASTLANE AUTH] Failed to parse cookies from \(cookieFilePath): \(error)".red)
            return
        }
    }
}
