;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/crypto/otp/core tests
;;; Vectors: RFC 4226 https://www.rfc-editor.org/rfc/rfc4226 Appendix D,
;;; RFC 6238 https://www.rfc-editor.org/rfc/rfc6238 Appendix B,
;;; https://github.com/google/google-authenticator/wiki/Key-Uri-Format
(import :std/test
        :std/error
        ./core)
(export core-test)

;; RFC 4226 Appendix D secret; also the RFC 6238 Appendix B SHA1 seed.
(def rfc-sha1-key (string->bytes "12345678901234567890"))
;; RFC 6238 Appendix B seeds for HMAC-SHA256 (32 bytes) and HMAC-SHA512 (64 bytes).
(def rfc-sha256-key (string->bytes "12345678901234567890123456789012"))
(def rfc-sha512-key
  (string->bytes "1234567890123456789012345678901234567890123456789012345678901234"))
;; Key Uri Format: JBSWY3DPEHPK3PXP = "Hello!" DE AD BE EF.
(def hello-key #u8(72 101 108 108 111 33 #xDE #xAD #xBE #xEF))
;; Key Uri Format: HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ.
(def acme-key #u8(61 198 202 164 130 74 109 40 135 103 178 51 30 32 180 49 102 203 133 217))

(def core-test
  (test-suite "test :std/crypto/otp/core"
    (test-case "positional constructor validates key fields"
      (check (OtpKey #f "account" #u8() 'totp 'sha1 6 30 0) =>! ContractViolation?)
      (check (OtpKey #f "account" rfc-sha1-key 'hotp 'sha1 6 30 -1) =>! ContractViolation?))

    (test-case "reject ambiguous otpauth account labels at construction"
      (check-function (lambda (issuer account)
                        (OtpKey issuer account rfc-sha1-key 'totp 'sha1 6 30 0))
        #f "a:b" =>! ContractViolation?
        "Example" " alice" =>! ContractViolation?
        "" " " =>! ContractViolation?))

    (test-case "RFC 4226 Appendix D HOTP vectors"
      (check-function hotp
        rfc-sha1-key 0 => "755224"
        rfc-sha1-key 1 => "287082"
        rfc-sha1-key 2 => "359152"
        rfc-sha1-key 3 => "969429"
        rfc-sha1-key 4 => "338314"
        rfc-sha1-key 5 => "254676"
        rfc-sha1-key 6 => "287922"
        rfc-sha1-key 7 => "162583"
        rfc-sha1-key 8 => "399871"
        rfc-sha1-key 9 => "520489"
        ;; oathtool(1): `oathtool -w 10 3132...3930` prints counter 10 as 403154.
        rfc-sha1-key 10 => "403154"))

    (test-case "digits: lengths and leading zeros"
      ;; Truncated decimals from RFC 4226 Appendix D Table 2:
      ;; counter 0 => 1284755224, counter 2 => 137359152, counter 7 => 82162583.
      (check-function hotp
        rfc-sha1-key 0 digits: 6 => "755224"
        rfc-sha1-key 0 digits: 7 => "4755224"
        rfc-sha1-key 0 digits: 8 => "84755224"
        rfc-sha1-key 0 digits: 10 => "1284755224"
        rfc-sha1-key 2 digits: 8 => "37359152"
        rfc-sha1-key 2 digits: 9 => "137359152"
        rfc-sha1-key 2 digits: 10 => "0137359152"
        rfc-sha1-key 7 digits: 8 => "82162583"
        rfc-sha1-key 7 digits: 9 => "082162583"
        rfc-sha1-key 7 digits: 10 => "0082162583"
        ;; RFC 6238 Appendix B: time 1111111109, SHA1, 8 digits, T = #x23523EC.
        rfc-sha1-key #x23523EC digits: 8 => "07081804")
      (check (string-length (hotp rfc-sha1-key (- (expt 2 64) 1))) => 6))

    (test-case "hotp: invalid arguments"
      (check-function hotp
        rfc-sha1-key -1 =>! ContractViolation?
        rfc-sha1-key (expt 2 64) =>! ContractViolation?
        rfc-sha1-key 0 digits: 5 =>! ContractViolation?
        rfc-sha1-key 0 digits: 11 =>! ContractViolation?
        rfc-sha1-key 0 algorithm: 'md5 =>! ContractViolation?
        rfc-sha1-key 0 algorithm: 'SHA1 =>! ContractViolation?))

    (test-case "totp-counter"
      ;; T column of RFC 6238 Appendix B.
      (check-function totp-counter
        59 => 1
        1111111109 => #x23523EC
        1111111111 => #x23523ED
        1234567890 => #x273EF07
        2000000000 => #x3F940AA
        20000000000 => #x27BC86AA
        0 => 0
        29 => 0
        30 => 1
        59 period: 60 => 0
        60 period: 60 => 1
        119 period: 60 => 1
        120 period: 60 => 2
        100 start: 40 => 2
        69 start: 40 => 0
        70 start: 40 => 1
        250 period: 60 start: 10 => 4
        ;; time before start: floor((time - start) / period)
        39 start: 40 => -1
        10 start: 40 => -1
        9 start: 40 => -2
        ;; Real time is floored and the result is exact.
        59.9 => 1
        60.0 => 2
        29.999 => 0)
      (check (exact? (totp-counter 59.9)) => #t))

    (test-case "RFC 6238 Appendix B TOTP vectors"
      (def (rfc6238 algorithm time)
        (totp (case algorithm
                ((sha1) rfc-sha1-key)
                ((sha256) rfc-sha256-key)
                ((sha512) rfc-sha512-key))
              time: time digits: 8 algorithm: algorithm))
      (check-function rfc6238
        'sha1   59 => "94287082"
        'sha256 59 => "46119246"
        'sha512 59 => "90693936"
        'sha1   1111111109 => "07081804"
        'sha256 1111111109 => "68084774"
        'sha512 1111111109 => "25091201"
        'sha1   1111111111 => "14050471"
        'sha256 1111111111 => "67062674"
        'sha512 1111111111 => "99943326"
        'sha1   1234567890 => "89005924"
        ;; oathtool --totp=SHA256 --digits=8 --now="2009-02-13 23:31:30 UTC" <seed32>
        'sha256 1234567890 => "91819424"
        ;; oathtool --totp=SHA512 --digits=8 --now="2009-02-13 23:31:30 UTC" <seed64>
        'sha512 1234567890 => "93441116"
        'sha1   2000000000 => "69279037"
        'sha256 2000000000 => "90698825"
        'sha512 2000000000 => "38618901"
        'sha1   20000000000 => "65353130"
        'sha256 20000000000 => "77737706"
        'sha512 20000000000 => "47863826")
      ;; Same vectors through hotp with T from the RFC table.
      (check-function hotp
        rfc-sha256-key #x273EF07 digits: 8 algorithm: 'sha256 => "91819424"
        rfc-sha512-key #x27BC86AA digits: 8 algorithm: 'sha512 => "47863826"
        rfc-sha1-key #x27BC86AA digits: 8 algorithm: 'sha1 => "65353130"))

    (test-case "totp parameters"
      ;; TOTP(T) = HOTP(T); 6-digit codes from RFC 4226 Appendix D.
      (check-function totp
        rfc-sha1-key time: 59 => "287082"
        rfc-sha1-key time: 59.9 => "287082"
        rfc-sha1-key time: 59.9 digits: 8 => "94287082"
        rfc-sha1-key time: 0 => "755224"
        rfc-sha1-key time: 119 period: 60 => "287082"
        rfc-sha1-key time: 100 start: 40 => "359152"
        rfc-sha1-key time: 250 period: 60 start: 10 => "338314"))

    (test-case "oathtool(1) examples"
      (check-function hotp
        ;; echo 00 | oathtool -
        #u8(0) 0 => "328482"
        ;; oathtool -b -c 5 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        ;; oathtool -c 5 3132333435363738393031323334353637383930
        rfc-sha1-key 5 => "254676")
      (check-function totp
        ;; oathtool --totp --now "2008-04-23 17:42:17 UTC" 00   (= 1208972537)
        #u8(0) time: 1208972537 => "974945")
      ;; oathtool -w 10 3132333435363738393031323334353637383930 969429  => 3
      (check (hotp-validate rfc-sha1-key "969429" window: 10) => 3)
      ;; TODO: oathtool --totp --now="2005-03-18 01:58:29 UTC" -w 10000000 <key> 89005924
      ;; prints 4115227; too slow to search interpreted, and oathtool reports an unsigned offset.
      )

    (test-case "hotp-validate"
      (check-function hotp-validate
        rfc-sha1-key "755224" => 0
        rfc-sha1-key "969429" => #f
        rfc-sha1-key "969429" window: 2 => #f
        rfc-sha1-key "969429" window: 3 => 3
        rfc-sha1-key "969429" window: 10 => 3
        rfc-sha1-key "969429" counter: 3 => 3
        rfc-sha1-key "969429" counter: 2 window: 1 => 3
        rfc-sha1-key "969429" counter: 4 window: 6 => #f
        rfc-sha1-key "403154" window: 10 => 10
        rfc-sha1-key "403154" counter: 5 window: 5 => 10
        rfc-sha1-key "520489" counter: 9 => 9
        rfc-sha1-key "000000" window: 0 => #f
        rfc-sha1-key "94287082" counter: 1 digits: 8 => 1
        rfc-sha1-key "287082" counter: 1 digits: 8 => #f
        rfc-sha256-key "91819424" counter: #x273EF00 window: 10 digits: 8 algorithm: 'sha256
        => #x273EF07))

    (test-case "totp-validate"
      ;; At time 59 the step is 1; steps 0..3 have the RFC 4226 counter 0..3 codes.
      (check-function totp-validate
        rfc-sha1-key "287082" time: 59 => 0
        rfc-sha1-key "755224" time: 59 => #f
        rfc-sha1-key "755224" time: 59 window: 1 => -1
        rfc-sha1-key "359152" time: 59 => #f
        rfc-sha1-key "359152" time: 59 window: 1 => 1
        rfc-sha1-key "969429" time: 59 window: 1 => #f
        rfc-sha1-key "969429" time: 59 window: 2 => 2
        rfc-sha1-key "969429" time: 59 window: 5 => 2
        rfc-sha1-key "338314" time: 179 window: 3 => -1
        rfc-sha1-key "969429" time: 179 window: 1 => #f
        rfc-sha1-key "969429" time: 179 window: 3 => -2
        rfc-sha1-key "969429" time: 119 period: 60 window: 1 => #f
        rfc-sha1-key "359152" time: 119 period: 60 window: 1 => 1
        rfc-sha1-key "287082" time: 100 start: 40 window: 1 => -1
        rfc-sha1-key "07081804" time: 1111111109 digits: 8 => 0
        rfc-sha1-key "14050471" time: 1111111109 digits: 8 window: 1 => 1
        rfc-sha1-key "07081804" time: 1111111111 digits: 8 window: 1 => -1
        rfc-sha512-key "47863826" time: 20000000000 digits: 8 algorithm: 'sha512 => 0
        ;; Steps before 0 are skipped, not errors.
        rfc-sha1-key "287082" time: 10 window: 1 => 1
        rfc-sha1-key "000000" time: 10 window: 2 => #f))

    (test-case "new-otp-key defaults, accessors and otp-key-code"
      (let (k (new-otp-key hello-key))
        (check (OtpKey? k) => #t)
        (check (OtpKey-issuer k) => #f)
        (check (OtpKey-account k) => "")
        (check (OtpKey-secret k) => hello-key)
        (check (OtpKey-type k) => 'totp)
        (check (OtpKey-algorithm k) => 'sha1)
        (check (OtpKey-digits k) => 6)
        (check (OtpKey-period k) => 30)
        (check (OtpKey-counter k) => 0))
      (let (k (new-otp-key acme-key issuer: "ACME Co" account: "john.doe@email.com"
                           type: 'hotp algorithm: 'sha256 digits: 8 period: 60 counter: 7))
        (check (OtpKey-issuer k) => "ACME Co")
        (check (OtpKey-account k) => "john.doe@email.com")
        (check (OtpKey-secret k) => acme-key)
        (check (OtpKey-type k) => 'hotp)
        (check (OtpKey-algorithm k) => 'sha256)
        (check (OtpKey-digits k) => 8)
        (check (OtpKey-period k) => 60)
        (check (OtpKey-counter k) => 7))
      (check (new-otp-key hello-key issuer: "Example" account: "alice@google.com")
             => (new-otp-key hello-key account: "alice@google.com" issuer: "Example"
                             type: 'totp algorithm: 'sha1 digits: 6 period: 30 counter: 0))
      (check-function otp-key-code
        (new-otp-key rfc-sha1-key digits: 8) time: 59 => "94287082"
        (new-otp-key rfc-sha512-key algorithm: 'sha512 digits: 8) time: 2000000000 => "38618901"
        (new-otp-key rfc-sha1-key period: 60) time: 119 => "287082"
        (new-otp-key #u8(0)) time: 1208972537 => "974945"
        ;; hotp keys use their counter and ignore the time.
        (new-otp-key rfc-sha1-key type: 'hotp counter: 3) => "969429"
        (new-otp-key rfc-sha1-key type: 'hotp counter: 3) time: 59 => "969429"
        (new-otp-key rfc-sha1-key type: 'hotp) => "755224"
        (new-otp-key rfc-sha256-key type: 'hotp algorithm: 'sha256 digits: 8 counter: #x273EF07)
        => "91819424"))

    ;; Printing a key must not reveal its reusable secret, in any rendering,
    ;; while equal? still compares the secret.
    (test-case "OtpKey printing omits the secret; equal? compares it"
      (def k (new-otp-key hello-key issuer: "Example" account: "alice@google.com"))
      (def (printed proc) (call-with-output-string (cut proc k <>)))
      (def (leaks? text)
        (or (string-contains text "#u8")
            (string-contains text "72 101 108")
            (string-contains text "JBSWY3DP")
            (string-contains text "48656c6c6f")))
      (check-function (lambda (proc) (leaks? (printed proc)))
        write => #f
        display => #f)
      (check (string-contains (printed write) "alice@google.com") ? number?)
      (check (equal? k (new-otp-key (u8vector-copy hello-key)
                                    issuer: "Example" account: "alice@google.com"))
             => #t)
      (check (equal? k (new-otp-key rfc-sha1-key issuer: "Example" account: "alice@google.com"))
             => #f))

    (test-case "new-otp-key validation"
      (check-function new-otp-key
        hello-key type: 'motp =>! ContractViolation?
        hello-key type: 'TOTP =>! ContractViolation?
        hello-key algorithm: 'md5 =>! ContractViolation?
        hello-key algorithm: 'SHA1 =>! ContractViolation?
        hello-key digits: 5 =>! ContractViolation?
        hello-key digits: 11 =>! ContractViolation?
        hello-key period: 0 =>! ContractViolation?
        hello-key period: -30 =>! ContractViolation?
        hello-key counter: -1 =>! ContractViolation?
        hello-key type: 'hotp counter: -1 =>! ContractViolation?
        ;; an empty secret has no otpauth:// URI that otpauth->otp-key accepts
        #u8() =>! ContractViolation?
        #u8() type: 'hotp =>! ContractViolation?)
      ;; the low-level primitives keep accepting an empty secret
      (check (string? (hotp #u8() 0)) => #t))

    (test-case "otpauth->otp-key: Key Uri Format examples"
      (check-function otpauth->otp-key
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        => (new-otp-key hello-key issuer: "Example" account: "alice@google.com")
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
        => (new-otp-key acme-key issuer: "ACME Co" account: "john.doe@email.com")))

    (test-case "otpauth->otp-key: labels"
      (check-function otpauth->otp-key
        ;; account only
        "otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP"
        => (new-otp-key hello-key account: "alice@google.com")
        "otpauth://totp/alice%40google.com?secret=JBSWY3DPEHPK3PXP"
        => (new-otp-key hello-key account: "alice@google.com")
        ;; issuer from the label prefix when the parameter is absent
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP"
        => (new-otp-key hello-key issuer: "Example" account: "alice@google.com")
        "otpauth://totp/Provider1:Alice%20Smith?secret=JBSWY3DPEHPK3PXP&issuer=Provider1"
        => (new-otp-key hello-key issuer: "Provider1" account: "Alice Smith")
        ;; %3A colon and %20 spaces before the account name
        "otpauth://totp/Big%20Corporation%3A%20alice%40bigco.com?secret=JBSWY3DPEHPK3PXP&issuer=Big%20Corporation"
        => (new-otp-key hello-key issuer: "Big Corporation" account: "alice@bigco.com")
        "otpauth://totp/Big%20Corporation%3Aalice%40bigco.com?secret=JBSWY3DPEHPK3PXP"
        => (new-otp-key hello-key issuer: "Big Corporation" account: "alice@bigco.com")
        "otpauth://totp/Example:%20%20alice?secret=JBSWY3DPEHPK3PXP"
        => (new-otp-key hello-key issuer: "Example" account: "alice")
        "otpauth://totp/Example: alice?secret=JBSWY3DPEHPK3PXP"
        => (new-otp-key hello-key issuer: "Example" account: "alice")
        ;; issuer parameter without a label prefix
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        => (new-otp-key hello-key issuer: "Example" account: "alice")
        ;; the issuer parameter wins over a different label prefix
        "otpauth://totp/Old:alice?secret=JBSWY3DPEHPK3PXP&issuer=New"
        => (new-otp-key hello-key issuer: "New" account: "alice")
        ;; percent-encoded reserved characters in the issuer parameter
        "otpauth://totp/Smith%20%26%20Wesson:bob?secret=JBSWY3DPEHPK3PXP&issuer=Smith%20%26%20Wesson"
        => (new-otp-key hello-key issuer: "Smith & Wesson" account: "bob")))

    (test-case "otpauth->otp-key: parameters"
      (check-function otpauth->otp-key
        ;; case-insensitive algorithm, digits, period, any parameter order
        "otpauth://totp/Example:alice?algorithm=sha256&digits=8&period=60&secret=JBSWY3DPEHPK3PXP&issuer=Example"
        => (new-otp-key hello-key issuer: "Example" account: "alice"
                        algorithm: 'sha256 digits: 8 period: 60)
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=Sha512"
        => (new-otp-key hello-key issuer: "Example" account: "alice" algorithm: 'sha512)
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256"
        => (new-otp-key hello-key issuer: "Example" account: "alice" algorithm: 'sha256)
        ;; hotp with counter
        "otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&counter=42"
        => (new-otp-key hello-key issuer: "Example" account: "alice" type: 'hotp counter: 42)
        "otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=0"
        => (new-otp-key hello-key account: "alice" type: 'hotp)
        ;; unknown parameters are ignored
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&image=https%3A%2F%2Fexample.com%2Flogo.png&foo=bar"
        => (new-otp-key hello-key issuer: "Example" account: "alice")
        ;; lenient Base32 secrets: lowercase, spaces, padding
        "otpauth://totp/alice?secret=jbswy3dpehpk3pxp"
        => (new-otp-key hello-key account: "alice")
        "otpauth://totp/alice?secret=jbsw%20y3dp%20ehpk%203pxp"
        => (new-otp-key hello-key account: "alice")
        "otpauth://totp/alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        => (new-otp-key rfc-sha1-key account: "alice")
        "otpauth://totp/alice?secret=AA"
        => (new-otp-key #u8(0) account: "alice")
        "otpauth://totp/alice?secret=AA%3D%3D%3D%3D%3D%3D"
        => (new-otp-key #u8(0) account: "alice")
        "otpauth://totp/alice?secret=AA======"
        => (new-otp-key #u8(0) account: "alice")))

    (test-case "otpauth->otp-key: errors"
      (check-function otpauth->otp-key
        "http://totp/Example:alice?secret=JBSWY3DPEHPK3PXP" =>! ContractViolation?
        "otpauth:totp/Example:alice?secret=JBSWY3DPEHPK3PXP" =>! ContractViolation?
        "otpauth://motp/Example:alice?secret=JBSWY3DPEHPK3PXP" =>! ContractViolation?
        "otpauth://totp/Example:alice" =>! ContractViolation?
        "otpauth://totp/Example:alice?issuer=Example" =>! ContractViolation?
        "otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP" =>! ContractViolation?
        "otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&counter=abc" =>! ContractViolation?
        "otpauth://hotp/Example:alice?secret=JBSWY3DPEHPK3PXP&counter=-1" =>! ContractViolation?
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=abc" =>! ContractViolation?
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=5" =>! ContractViolation?
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&period=0" =>! ContractViolation?
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&period=" =>! ContractViolation?
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5" =>! ContractViolation?
        "otpauth://totp/Example:alice?secret=JBSWY3DP1HPK3PXP" =>! ContractViolation?
        "otpauth://totp/Example:alice?secret=JBSWY3DPE" =>! ContractViolation?
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=%G1" =>! ContractViolation?))

    (test-case "otp-key->otpauth canonical form"
      (check-function otp-key->otpauth
        (new-otp-key acme-key issuer: "ACME Co" account: "john.doe@email.com")
        => "otpauth://totp/ACME%20Co:john.doe%40email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30"
        (new-otp-key hello-key issuer: "Example" account: "alice@google.com")
        => "otpauth://totp/Example:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30"
        (new-otp-key hello-key account: "alice@google.com" type: 'hotp
                     algorithm: 'sha256 digits: 8 counter: 42)
        => "otpauth://hotp/alice%40google.com?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&counter=42"
        (new-otp-key #u8(0) issuer: "Smith & Wesson" account: "bob" algorithm: 'sha512 period: 60)
        => "otpauth://totp/Smith%20%26%20Wesson:bob?secret=AA&issuer=Smith%20%26%20Wesson&algorithm=SHA512&digits=6&period=60"))

    (test-case "otpauth round trips"
      (for-each
       (lambda (k)
         (check (otpauth->otp-key (otp-key->otpauth k)) => k))
       (list (new-otp-key hello-key)
             (new-otp-key hello-key account: " alice")
             (new-otp-key hello-key issuer: "Example" account: "a:b")
             (new-otp-key hello-key issuer: "" account: "")
             (new-otp-key hello-key issuer: "Example" account: "alice@google.com")
             (new-otp-key acme-key issuer: "ACME Co" account: "john.doe@email.com")
             (new-otp-key acme-key issuer: "Big Corporation" account: "Alice Smith"
                          algorithm: 'sha256 digits: 8 period: 60)
             (new-otp-key rfc-sha512-key issuer: "Smith & Wesson" account: "a=b&c?d/e#f%g+h"
                          algorithm: 'sha512 digits: 10 period: 15)
             (new-otp-key rfc-sha1-key account: "alice" type: 'hotp counter: 42)
             (new-otp-key rfc-sha1-key issuer: "Example" account: "bob" type: 'hotp
                          algorithm: 'sha256 digits: 7 counter: (- (expt 2 64) 1))
             (new-otp-key #u8(0) account: "zero")
             (new-otp-key #u8(1 2 3 4) issuer: "Ünïcödé" account: "日本"))))))
