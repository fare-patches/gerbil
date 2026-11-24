;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HOTP/TOTP one-time passwords: facade
;;; RFC 4226 HOTP: https://www.rfc-editor.org/rfc/rfc4226
;;; RFC 6238 TOTP: https://www.rfc-editor.org/rfc/rfc6238
;;; Key Uri Format: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
;;; See otp.md for the documentation.
(import ./otp/core
        ./otp/keyring
        ./otp/cli)
(export (import: ./otp/core)
        (import: ./otp/keyring)
        (import: ./otp/cli))
