import PromiseKit
import Foundation
import AppleAPI

public class AppleSessionService {

    private let xcodesUsername = "XCODES_USERNAME"
    private let xcodesPassword = "XCODES_PASSWORD"

    var configuration: Configuration

    public init(configuration: Configuration) {
        self.configuration = configuration
    }

    private func findUsername() -> String? {
        Current.logging.log("🔍 [AUTH] Looking for username...")
        if let username = Current.shell.env(xcodesUsername) {
            Current.logging.log("✅ [AUTH] Found username in \(xcodesUsername) environment variable")
            return username
        }
        else if let username = configuration.defaultUsername {
            Current.logging.log("✅ [AUTH] Found username in configuration: \(username)")
            return username
        }
        Current.logging.log("⚠️ [AUTH] No username found")
        return nil
    }

    private func findPassword(withUsername username: String, noKeychain: Bool) -> String? {
        Current.logging.log("🔍 [AUTH] Looking for password for username: \(username)")
        if let password = Current.shell.env(xcodesPassword) {
            Current.logging.log("✅ [AUTH] Found password in \(xcodesPassword) environment variable")
            return password
        }
        else if !noKeychain, let password = try? Current.keychain.getString(username){
            Current.logging.log("✅ [KEYCHAIN] Found password in keychain for username: \(username)")
            return password
        }
        if noKeychain {
            Current.logging.log("⚠️ [AUTH] No password found (keychain disabled)")
        } else {
            Current.logging.log("⚠️ [AUTH] No password found")
        }
        return nil
    }

    func validateADCSession(path: String) -> Promise<Void> {
        return Current.network.dataTask(with: URLRequest.downloadADCAuth(path: path)).asVoid()
    }

    func loginIfNeeded(withUsername providedUsername: String? = nil, shouldPromptForPassword: Bool = false, noKeychain: Bool) -> Promise<Void> {
        Current.logging.log("🔑 [AUTH] loginIfNeeded called with providedUsername: \(providedUsername ?? "nil"), shouldPromptForPassword: \(shouldPromptForPassword), noKeychain: \(noKeychain)")
        return firstly { () -> Promise<Void> in
            Current.logging.log("🔑 [AUTH] Validating session...")
            return Current.network.validateSession()
        }
        .done { _ in
            Current.logging.log("✅ [AUTH] Session is valid, no login needed")
        }
        // Don't have a valid session, so we'll need to log in
        .recover { error -> Promise<Void> in
            Current.logging.log("⚠️ [AUTH] Session validation failed with error: \(error)")
            Current.logging.log("🔑 [AUTH] Attempting to login...")
            var possibleUsername = providedUsername ?? self.findUsername()
            Current.logging.log("🔑 [AUTH] Found username: \(possibleUsername ?? "nil")")
            var hasPromptedForUsername = false
            if possibleUsername == nil {
                Current.logging.log("🔑 [AUTH] No username found, prompting user...")
                possibleUsername = Current.shell.readLine(prompt: "Apple ID: ")
                hasPromptedForUsername = true
            }
            guard let username = possibleUsername else {
                Current.logging.log("❌ [AUTH] No username available, throwing error")
                throw Error.missingUsernameOrPassword
            }
            Current.logging.log("🔑 [AUTH] Using username: \(username)")

            let passwordPrompt: String
            if hasPromptedForUsername {
                passwordPrompt = "Apple ID Password: "
            } else {
                // If the user wasn't prompted for their username, also explain which Apple ID password they need to enter
                passwordPrompt = "Apple ID Password (\(username)): "
            }
            Current.logging.log("🔑 [AUTH] Looking for password...")
            var possiblePassword = self.findPassword(withUsername: username, noKeychain: noKeychain)
            Current.logging.log("🔑 [AUTH] Password found: \(possiblePassword != nil)")
            if possiblePassword == nil || shouldPromptForPassword {
                Current.logging.log("🔑 [AUTH] No password found or should prompt, prompting user...")
                possiblePassword = Current.shell.readSecureLine(prompt: passwordPrompt)
            }
            guard let password = possiblePassword else {
                Current.logging.log("❌ [AUTH] No password available, throwing error")
                throw Error.missingUsernameOrPassword
            }
            Current.logging.log("🔑 [AUTH] Password obtained, proceeding with login...")

            return firstly { () -> Promise<Void> in
                self.login(username, password: password, noKeychain: noKeychain)
            }
            .recover { error -> Promise<Void> in
                Current.logging.log(error.legibleLocalizedDescription.red)

                if case Client.Error.invalidUsernameOrPassword = error {
                    Current.logging.log("Try entering your password again")
                    // Prompt for the password next time to avoid being stuck in a loop of using an incorrect XCODES_PASSWORD environment variable
                    return self.loginIfNeeded(withUsername: username, shouldPromptForPassword: true, noKeychain: noKeychain)
                }
                else {
                    return Promise(error: error)
                }
            }
        }
    }

    func login(_ username: String, password: String, noKeychain: Bool) -> Promise<Void> {
        Current.logging.log("🔑 [AUTH] Attempting to login with username: \(username), noKeychain: \(noKeychain)")
        return firstly { () -> Promise<Void> in
            Current.network.login(accountName: username, password: password)
        }
        .recover { error -> Promise<Void> in
            Current.logging.log("❌ [AUTH] Login failed with error: \(error)")

            if let error = error as? Client.Error {
                switch error  {
                    case .invalidUsernameOrPassword(_):
                        // remove any keychain password if we fail to log with an invalid username or password so it doesn't try again.
                        if !noKeychain {
                            Current.logging.log("🔐 [KEYCHAIN] Removing invalid password from keychain for username: \(username)")
                            try? Current.keychain.remove(username)
                        } else {
                            Current.logging.log("🔐 [KEYCHAIN] Skipping keychain removal (keychain disabled)")
                        }
                    default:
                        break
                }
            }

            return Promise(error: error)
        }
        .done { _ in
            Current.logging.log("✅ [AUTH] Login successful")
            if !noKeychain {
                Current.logging.log("🔐 [KEYCHAIN] Saving password to keychain for username: \(username)")
                try? Current.keychain.set(password, key: username)
            } else {
                Current.logging.log("🔐 [KEYCHAIN] Skipping keychain save (keychain disabled)")
            }

            if self.configuration.defaultUsername != username {
                Current.logging.log("💾 [CONFIG] Saving default username to configuration")
                self.configuration.defaultUsername = username
                try? self.configuration.save()
            }
        }
    }

    public func logout(noKeychain: Bool) -> Promise<Void> {
        Current.logging.log("🔑 [AUTH] Logging out...")
        guard let username = findUsername() else {
            Current.logging.log("❌ [AUTH] Cannot logout, no username found")
            return Promise<Void>(error: Client.Error.notAuthenticated)
        }

        return Promise { seal in
            // Remove cookies in the shared URLSession
            Current.logging.log("🍪 [AUTH] Resetting URLSession cookies...")
            AppleAPI.Current.network.session.reset {
                seal.fulfill(())
            }
        }
        .done {
            // Remove all keychain items
            if !noKeychain {
                Current.logging.log("🔐 [KEYCHAIN] Removing password from keychain for username: \(username)")
                try Current.keychain.remove(username)
            } else {
                Current.logging.log("🔐 [KEYCHAIN] Skipping keychain removal (keychain disabled)")
            }

            // Set `defaultUsername` in Configuration to nil
            Current.logging.log("💾 [CONFIG] Clearing default username from configuration")
            self.configuration.defaultUsername = nil
            try self.configuration.save()
            Current.logging.log("✅ [AUTH] Logout complete")
        }
    }
}

extension AppleSessionService {
    enum Error: LocalizedError, Equatable {
        case missingUsernameOrPassword

        public var errorDescription: String? {
            switch self {
                case .missingUsernameOrPassword:
                    return "Missing username or a password. Please try again."
            }
        }

    }
}
