;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/crypto/otp/cli tests
;;; Vectors: RFC 4226 https://www.rfc-editor.org/rfc/rfc4226 Appendix D,
;;; RFC 6238 https://www.rfc-editor.org/rfc/rfc6238 Appendix B,
;;; oathtool(1) https://www.nongnu.org/oath-toolkit/oathtool.1.html examples.
(import :std/test
        :std/error
        :std/cli/multicall
        (only-in :std/io/tempfile call-with-temporary-file-name)
        :std/encoding/base32
        :std/encoding/hex
        (only-in :std/text/parser/ll1 ll1)
        (only-in :std/text/parser/base parse-error?)
        ./core
        ./keyring
        ./cli)
(export cli-test)

;; RFC 4226 Appendix D secret; also the RFC 6238 Appendix B SHA1 seed.
(def rfc-sha1-key (string->bytes "12345678901234567890"))
(def rfc-sha1-hex "3132333435363738393031323334353637383930")
;; RFC 6238 Appendix B seeds for HMAC-SHA256 (32 bytes) and HMAC-SHA512 (64 bytes).
(def rfc-sha256-key (string->bytes "12345678901234567890123456789012"))
(def rfc-sha512-key
  (string->bytes "1234567890123456789012345678901234567890123456789012345678901234"))
(def rfc-sha256-hex (hex-encode rfc-sha256-key))

;; Seconds of the DURATION argument str, as the CLI parses it.
(def (otp-duration str)
  (ll1 ll1-otp-duration str))

(def (call-with-otp-main proc)
  (let ((entries (hash->list entry-points))
        (default multicall-default)
        (fallback? multicall-fallback?))
    (unwind-protect
      (let ()
        (define-otp-main)
        (proc main))
      (begin
        (hash-clear! entry-points)
        (for-each (lambda (e) (hash-put! entry-points (car e) (cdr e))) entries)
        (set-default-entry-point! default fallback: fallback?)))))

;; Run a multicall command line; return [stdout stderr results], where results
;; is the list of the values the entry point returned.
(def (run-cli . args)
  (let ((out (open-output-string))
        (err (open-output-string)))
    (let (results (parameterize ((current-output-port out)
                                 (current-error-port err))
                    (call-with-otp-main
                     (lambda (_)
                       (call-with-values (lambda () (apply dispatch-entry-point args)) list)))))
      [(get-output-string out) (get-output-string err) results])))

;; Success: each line printed to stdout, nothing to stderr, (void) returned.
(def (ok . lines)
  [(apply string-append (map (lambda (line) (string-append line "\n")) lines))
   ""
   [(void)]])

;; Failed validation: no output at all, (values) returned.
(def failed ["" "" []])

;; No matching key: nothing on stdout, the message on stderr, (values) returned.
(def (no-match? result)
  (match result
    (["" err []] (and (string-contains err "No matching OTP key") #t))
    (_ #f)))

;; A totp otpauth:// URI for issuer "rfc", 8 digits.
(def (rfc-totp-uri account secret algorithm)
  (string-append "otpauth://totp/rfc:" account
                 "?secret=" (base32-encode secret padding: #f)
                 "&issuer=rfc&algorithm=" algorithm "&digits=8"))

;; Keys, in order; search texts "rfc sha1", "rfc sha256", "rfc sha512",
;; "rfc hotp" (hotp, counter 5, 6 digits) and "solo@example.org" (no issuer).
(def rfc-keyring-items
  [(rfc-totp-uri "sha1" rfc-sha1-key "SHA1")
   (rfc-totp-uri "sha256" rfc-sha256-key "SHA256")
   (rfc-totp-uri "sha512" rfc-sha512-key "SHA512")
   (string-append "otpauth://hotp/rfc:hotp?secret=" (base32-encode rfc-sha1-key padding: #f)
                  "&issuer=rfc&counter=5")
   (string-append "otpauth://totp/solo@example.org?secret="
                  (base32-encode rfc-sha1-key padding: #f) "&digits=8")])

;; Call thunk with current-otp-keyring bound to a fresh keyring of the RFC keys.
(def (call-with-rfc-keyring thunk)
  (let (keyring (new-memory-otp-keyring))
    (otp-keyring-register! keyring rfc-keyring-items)
    (parameterize ((current-otp-keyring keyring))
      (thunk))))

(defrule (with-rfc-keyring body ...)
  (call-with-rfc-keyring (lambda () body ...)))

;; Call thunk with the path of a fresh temporary file holding contents.
(def (call-with-temporary-file contents thunk)
  (call-with-temporary-file-name "gerbil-otp-cli-test-"
    (lambda (path)
      (call-with-output-file path (lambda (port) (display contents port)))
      (thunk path)
      path)
    suffix: ".key"))

(def cli-test
  (test-suite "test :std/crypto/otp/cli"
    (test-case "define-otp-main registers commands and enables key search as the default"
      (call-with-otp-main
       (lambda (main)
         (check (procedure? main) => #t)
         (check multicall-default => 'keys)
         (check multicall-fallback? => #t)
         (check (filter (cut hash-key? entry-points <>) '(keys otpauth generate verify))
                => '(keys otpauth generate verify)))))

    (test-case "parse-otp-time: epoch seconds"
      (check-function parse-otp-time
        "@0" => 0
        "@59" => 59
        "@-1" => -1
        "@1234567890" => 1234567890
        ;; RFC 6238 Appendix B: beyond 32 bits.
        "@20000000000" => 20000000000))

    (test-case "parse-otp-time: calendar timestamps"
      (check-function parse-otp-time
        ;; RFC 6238 Appendix B: 1234567890 is 2009-02-13 23:31:30 UTC.
        "2009-02-13T23:31:30Z" => 1234567890
        "2009-02-13T23:31:30z" => 1234567890
        "2009-02-13 23:31:30Z" => 1234567890
        "2009-02-13T23:31:30+00:00" => 1234567890
        "2009-02-13T23:31:30-00:00" => 1234567890
        "2009-02-13T23:31:30+01:00" => 1234564290
        "2009-02-14T00:31:30+01:00" => 1234567890
        "1969-12-31T23:00:00-0100" => 0
        "1970-01-01T01:00:00+0100" => 0
        "1970-01-01 UTC" => 0
        ;; RFC 6238 Appendix B: 1111111109 is 2005-03-18 01:58:29 UTC.
        "2005-03-18T01:58:29Z" => 1111111109
        "1970-01-01T00:00:59Z" => 59))

    (test-case "parse-otp-time: date-times and dates without offset are UTC"
      (check-function parse-otp-time
        "2009-02-13 23:31:30" => 1234567890
        "2009-02-13T23:31:30" => 1234567890
        ;; Seconds default to zero.
        "2009-02-13 23:31" => 1234567860
        ;; Dates alone are midnight UTC.
        "1970-01-01" => 0
        "1970-01-02" => 86400
        "2009-02-13" => 1234483200))

    (test-case "parse-otp-time: oathtool UTC suffix"
      (check-function parse-otp-time
        ;; oathtool(1) example.
        "2008-04-23 17:42:17 UTC" => 1208972537
        "2009-02-13 23:31:30 UTC" => 1234567890
        "2009-02-13T23:31:30 UTC" => 1234567890
        "2005-03-18 01:58:29 UTC" => 1111111109
        "1970-01-01 00:00:59 UTC" => 59))

    (test-case "parse-otp-time: now"
      (check (parse-otp-time "now") ? exact-integer?))

    (test-case "parse-otp-time: invalid"
      (check-function parse-otp-time
        "" =>! parse-error?
        ;; Bare digits are ambiguous; oathtool rejects them too.
        "0" =>! parse-error?
        "59" =>! parse-error?
        "-1" =>! parse-error?
        "1234567890" =>! parse-error?
        "@" =>! parse-error?
        "-" =>! parse-error?
        "@-" =>! parse-error?
        "@--1" =>! parse-error?
        "--1" =>! parse-error?
        "1.5" =>! parse-error?
        "@1.5" =>! parse-error?
        "@59 " =>! parse-error?
        "12a" =>! parse-error?
        " 59" =>! parse-error?
        " @59" =>! parse-error?
        "now " =>! parse-error?
        "yesterday" =>! parse-error?
        ;; The oathtool suffix is exactly " UTC".
        "2009-02-13 23:31:30UTC" =>! parse-error?
        "2009-02-13 23:31:30 PST" =>! parse-error?
        "2009-02-13 23:31:30 UTC junk" =>! parse-error?
        "1970-01-01T12:00+24:00" =>! parse-error?
        "1970-01-01T12:00-00:60" =>! parse-error?
        "1970-01-01T12:00Z UTC" =>! parse-error?
        ;; A date with a UTC offset needs a time.
        "1970-01-01Z" =>! parse-error?
        ;; Named-zone annotations are outside the CLI grammar.
        "2009-02-13T23:31:30[UTC]" =>! parse-error?
        "2009-02-30T00:00:00Z" =>! parse-error?
        "2009-02-13T24:31:30Z" =>! parse-error?))

    (test-case "ll1-otp-duration"
      (check-function otp-duration
        "30" => 30
        "30s" => 30
        "1" => 1
        "90s" => 90
        "1m" => 60
        "2m" => 120
        "1h" => 3600
        "24h" => 86400))

    (test-case "ll1-otp-duration: invalid"
      (check-function otp-duration
        "" =>! parse-error?
        "s" =>! parse-error?
        "0" =>! parse-error?
        "0s" =>! parse-error?
        "0m" =>! parse-error?
        "-30" =>! parse-error?
        "1.5m" =>! parse-error?
        "30 s" =>! parse-error?
        "1d" =>! parse-error?
        "m" =>! parse-error?))

    (test-case "generate and verify one-off secrets"
      (check-function run-cli
        "generate" "--time" "@59" "--digits" "8" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        => (ok "94287082")
        "generate" "--mode" "hotp" "--encoding" "hex" "--window" "1" rfc-sha1-hex
        => (ok "755224" "287082")
        "verify" "--mode" "hotp" "--encoding" "hex" "--window" "3" rfc-sha1-hex "969429"
        => (ok "3")
        "verify" "--time" "@59" "--window" "1" "--encoding" "hex" rfc-sha1-hex "755224"
        => (ok "-1")
        "verify" "--time" "@59" "--encoding" "hex" rfc-sha1-hex "000000" => failed
        "generate" "--hash" "sha256" "--encoding" "hex" "--digits" "8"
        "--start" "@60" "--period" "1m" "--time" "@179" rfc-sha256-hex => (ok "46119246"))
      (parameterize ((current-input-port (open-input-string "00\n")))
        (check (run-cli "generate" "--mode" "hotp" "--encoding" "hex" "-") => (ok "328482")))
      (call-with-temporary-file "00\n"
        (lambda (path)
          (check (run-cli "generate" "--mode" "hotp" "--encoding" "hex" (string-append "@" path))
                 => (ok "328482")))))

    (test-case "keys: RFC 6238 codes at fixed times"
      (with-rfc-keyring
       (check-function run-cli
         "keys" "--time" "@59" "rfc sha1" => (ok "94287082 rfc sha1")
         "keys" "-N" "@59" "rfc sha1" => (ok "94287082 rfc sha1")
         "keys" "--time" "@59" "sha256" => (ok "46119246 rfc sha256")
         "keys" "--time" "@59" "sha512" => (ok "90693936 rfc sha512")
         "keys" "--time" "2009-02-13 23:31:30 UTC" "sha"
         => (ok "89005924 rfc sha1" "91819424 rfc sha256" "93441116 rfc sha512")
         "keys" "-N" "@1111111109" "sha"
         => (ok "07081804 rfc sha1" "68084774 rfc sha256" "25091201 rfc sha512")
         ;; No issuer: just the account.
         "keys" "--time" "@59" "solo" => (ok "94287082 solo@example.org")
         ;; hotp keys print the code at their counter, 5.
         "keys" "--time" "@59" "hotp" => (ok "254676 rfc hotp")
         ;; No pattern: every key, in insertion order.
         "keys" "--time" "@59"
         => (ok "94287082 rfc sha1" "46119246 rfc sha256" "90693936 rfc sha512"
                "254676 rfc hotp" "94287082 solo@example.org"))))

    (test-case "keys: invalid TIME"
      (with-rfc-keyring
       (check-function run-cli
         ;; Bare digits are not a TIME: use @59.
         "keys" "--time" "59" "rfc sha1" =>! parse-error?
         "keys" "-N" "yesterday" "rfc sha1" =>! parse-error?)))

    (test-case "keys: window"
      (with-rfc-keyring
       (check-function run-cli
         ;; Steps 1 and 2 are HOTP counters 1 and 2: truncated 1094287082 137359152.
         "keys" "--time" "@59" "-w" "1" "rfc sha1" => (ok "94287082 37359152 rfc sha1")
         "keys" "--time" "@59" "--window" "2" "rfc sha1"
         => (ok "94287082 37359152 26969429 rfc sha1")
         "keys" "--time" "@59" "-w" "1" "sha256"
         => (ok (string-append "46119246 "
                               (totp rfc-sha256-key time: 89 digits: 8 algorithm: 'sha256)
                               " rfc sha256"))
         ;; hotp: the next counters, 6 and 7.
         "keys" "-w" "2" "hotp" => (ok "254676 287922 162583 rfc hotp"))))

    (test-case "keys: hotp counters are not incremented"
      (with-rfc-keyring
       (check-function run-cli
         "hotp" => (ok "254676 rfc hotp")
         "keys" "hotp" => (ok "254676 rfc hotp")
         "keys" "-w" "1" "hotp" => (ok "254676 287922 rfc hotp")
         "keys" "hotp" => (ok "254676 rfc hotp"))
       (check (map OtpKey-counter (OtpKeyring-find-keys (current-otp-keyring) "rfc hotp"))
              => [5])))

    (test-case "keys: patterns"
      (with-rfc-keyring
       (check-function run-cli
         ;; Case-insensitive.
         "keys" "--time" "@59" "RFC SHA1" => (ok "94287082 rfc sha1")
         "keys" "--time" "@59" "Solo@Example.ORG" => (ok "94287082 solo@example.org")
         ;; Several pattern arguments are joined with a space.
         "keys" "--time" "@59" "rfc" "sha1" => (ok "94287082 rfc sha1")
         "keys" "--time" "@59" "RFC" "SHA512" => (ok "90693936 rfc sha512")
         ;; Glob wildcards.
         "keys" "--time" "@59" "sha*2"
         => (ok "46119246 rfc sha256" "90693936 rfc sha512")
         "keys" "--time" "@59" "rfc?sha1" => (ok "94287082 rfc sha1"))
       (check-function no-match?
         (run-cli "keys" "--time" "@59" "nothing") => #t
         (run-cli "keys" "--time" "@59" "sha1" "rfc") => #t
         (run-cli "keys" "rfc" "sha3") => #t)))

    (test-case "keys visits repeatable matches in order and prints each key once"
      (with-rfc-keyring
       (check-function run-cli
         "keys" "-N" "@59" "--match" "solo" "-m" "sha*" "-m" "sha1" "rfc" "hotp"
         => (ok "94287082 solo@example.org" "94287082 rfc sha1" "46119246 rfc sha256"
                "90693936 rfc sha512" "254676 rfc hotp")
         "keys" "-m" "nothing" "--match" "hotp" => (ok "254676 rfc hotp"))
       (check (no-match? (run-cli "keys" "-m" "nothing" "-m" "absent")) => #t)))

    (test-case "keys: empty keyring"
      (parameterize ((current-otp-keyring (new-memory-otp-keyring)))
        (check-function no-match?
          (run-cli "keys") => #t
          (run-cli "keys" "anything") => #t)))

    (test-case "otpauth"
      (with-rfc-keyring
       (let (uri (lambda (item) (otp-key->otpauth (otpauth->otp-key item))))
         (check-function run-cli
           "otpauth" "rfc sha1" => (ok (uri (car rfc-keyring-items)))
           "otpauth" "RFC" "SHA256" => (ok (uri (cadr rfc-keyring-items)))
           "otpauth" "sha*2" => (ok (uri (cadr rfc-keyring-items))
                                    (uri (caddr rfc-keyring-items)))
           "otpauth" => (apply ok (map uri rfc-keyring-items))))
       (check (no-match? (run-cli "otpauth" "nothing")) => #t)))))
