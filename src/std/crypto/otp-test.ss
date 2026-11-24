;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test (only-in "../cli/exit-test-support" gxi-exit-code))
(export otp-test)

(def otp-test
  (test-suite "test :std/crypto/otp"
    (test-case "importing :std/crypto/otp registers no entry point"
      ;; Exit code of a child that imports the facade, runs setup, then exits
      ;; with the number of OTP entry points registered.
      (def (registered-otp-entry-points setup)
        (gxi-exit-code '(import :std/crypto/otp :std/cli/multicall)
                       setup
                       '(exit (length (filter (cut hash-key? entry-points <>)
                                              '(keys otpauth generate verify))))))
      (check-function registered-otp-entry-points
        '(void) => 0
        '(register-otp-entry-points!) => 4))))
