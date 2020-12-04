export class WebAuthnSupport {

    /**
     * Is WebAuthN API available?
     * @returns {Boolean} available
     */
    static isSupported() {
        return navigator.credentials && window.PublicKeyCredential &&
            typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function";
    }

    /**
     * Have the device any Biometric (User Verifying) Authenticator?
     * @returns {Promise<Boolean>} supported
     */
    static async isBiometricsSupported() {
        console.log("isSupported?")
        return this.isSupported() && await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    }
}