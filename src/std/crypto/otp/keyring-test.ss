;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/crypto/otp/keyring tests
(import :std/test
        :std/error
        ./core
        ./keyring)
(export keyring-test)

;; Key Uri Format: JBSWY3DPEHPK3PXP = "Hello!" DE AD BE EF.
(def hello-key #u8(72 101 108 108 111 33 #xDE #xAD #xBE #xEF))
;; RFC 4226 Appendix D secret; Base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
(def rfc-sha1-key (string->bytes "12345678901234567890"))

;; Searchable texts, downcased: "github.com fare", "gitlab fare@example.org",
;; "acme co john.doe@email.com", "alice@google.com" (no issuer), "boxcom bob".
(def gh (new-otp-key hello-key issuer: "github.com" account: "fare"))
(def gl (new-otp-key rfc-sha1-key issuer: "GitLab" account: "fare@example.org"))
(def acme (new-otp-key hello-key issuer: "ACME Co" account: "john.doe@email.com"))
(def solo (new-otp-key rfc-sha1-key account: "alice@google.com"))
(def boxcom (new-otp-key hello-key issuer: "Boxcom" account: "bob"))

;; A fresh memory keyring holding keys, added in order.
(def (keyring-of . keys)
  (let (kr (new-memory-otp-keyring))
    (for-each (lambda (k) (OtpKeyring-add-key! kr k)) keys)
    kr))

(def keyring-test
  (test-suite "test :std/crypto/otp/keyring"
    (test-case "empty keyring"
      (let (kr (new-memory-otp-keyring))
        (check (OtpKeyring? kr) => #t)
        (check (OtpKeyring-list-keys kr) => [])
        (check-function OtpKeyring-find-keys
          kr "" => []
          kr "git" => [])
        (check (OtpKeyring-remove-key! kr "github.com" "fare") => #f)
        (check (OtpKeyring-next-hotp-counter! kr gh) =>! ContractViolation?)))

    (test-case "add-key! and list-keys keep insertion order"
      (let (kr (new-memory-otp-keyring))
        (OtpKeyring-add-key! kr acme)
        (check (OtpKeyring-list-keys kr) => [acme])
        (OtpKeyring-add-key! kr gh)
        (OtpKeyring-add-key! kr solo)
        (OtpKeyring-add-key! kr gl)
        (check (OtpKeyring-list-keys kr) => [acme gh solo gl])))

    (test-case "add-key! with an existing identity replaces it in place"
      (let ((kr (keyring-of gh gl acme))
            (gh8 (new-otp-key rfc-sha1-key issuer: "github.com" account: "fare" digits: 8))
            (solo-hotp (new-otp-key hello-key account: "alice@google.com" type: 'hotp)))
        (OtpKeyring-add-key! kr gh8)
        (check (OtpKeyring-list-keys kr) => [gh8 gl acme])
        (OtpKeyring-add-key! kr solo)
        (OtpKeyring-add-key! kr solo-hotp)
        (check (OtpKeyring-list-keys kr) => [gh8 gl acme solo-hotp])))

    (test-case "identity is the (issuer, account) pair"
      (let* ((same-account (new-otp-key hello-key issuer: "gitlab.com" account: "fare"))
             (same-issuer (new-otp-key hello-key issuer: "github.com" account: "faré"))
             (no-issuer (new-otp-key hello-key account: "fare"))
             (empty-issuer (new-otp-key hello-key issuer: "" account: "fare"))
             (kr (keyring-of gh same-account same-issuer no-issuer empty-issuer)))
        ;; The empty issuer "" and the absent issuer #f are distinct identities.
        (check (OtpKeyring-list-keys kr)
               => [gh same-account same-issuer no-issuer empty-issuer])))

    (test-case "remove-key!"
      (let (kr (keyring-of gh gl acme solo))
        (check (OtpKeyring-remove-key! kr "GitLab" "fare@example.org") => #t)
        (check (OtpKeyring-list-keys kr) => [gh acme solo])
        (check-function OtpKeyring-remove-key!
          kr "GitLab" "fare@example.org" => #f
          ;; Identities match exactly: other issuer, other account, no issuer.
          kr "github.com" "alice@google.com" => #f
          kr "github.com" "nobody" => #f
          kr #f "fare" => #f)
        (check (OtpKeyring-list-keys kr) => [gh acme solo])
        (check-function OtpKeyring-remove-key!
          kr #f "alice@google.com" => #t
          kr "github.com" "fare" => #t)
        (check (OtpKeyring-list-keys kr) => [acme])
        (check (OtpKeyring-remove-key! kr "ACME Co" "john.doe@email.com") => #t)
        (check (OtpKeyring-list-keys kr) => [])
        ;; A removed identity can be added again, at the end.
        (OtpKeyring-add-key! kr gh)
        (OtpKeyring-add-key! kr acme)
        (check (OtpKeyring-list-keys kr) => [gh acme])))

    (test-case "find-keys: substring, case and glob matching"
      (let (kr (keyring-of gh gl acme solo boxcom))
        (def (find pattern) (OtpKeyring-find-keys kr pattern))
        (check-function find
          ;; the empty pattern matches every key, in insertion order
          "" => [gh gl acme solo boxcom]
          ;; case-insensitive, on both pattern and key
          "GIT" => [gh gl]
          "git" => [gh gl]
          "acme co" => [acme]
          "ACME CO" => [acme]
          "lab" => [gl]
          ;; substring across the issuer/account boundary
          "com fare" => [gh]
          "co john" => [acme]
          "x bob" => []
          "m bob" => [boxcom]
          ;; `*` and `?` inside the pattern
          "hub*fare" => [gh]
          "a*google" => [solo]
          "?lab" => [gl]
          "g?t" => [gh gl]
          "git???.com" => [gh]
          "git*fare" => [gh gl]
          ;; `.` is a literal character, not a regular expression wildcard
          ".com" => [gh acme solo]
          "xcom" => [boxcom]
          "b.com" => [gh]
          "?com" => [gh acme solo boxcom]
          ;; no match
          "nonexistent" => []
          "fare@example.com" => []))
      (check (OtpKeyring-find-keys (keyring-of gl gh) "git") => [gl gh]))

    (test-case "find-keys: a key without issuer matches on its account only"
      (let (kr (keyring-of solo gh))
        (def (find pattern) (OtpKeyring-find-keys kr pattern))
        (check-function find
          "alice" => [solo]
          "ALICE@GOOGLE.COM" => [solo]
          "?alice@google.com" => []
          " alice" => []
          "#f" => []
          "#f alice" => []
          "com" => [solo gh])))

    (test-case "next-hotp-counter!"
      (let* ((hk (new-otp-key rfc-sha1-key issuer: "Example" account: "bob"
                              type: 'hotp counter: 5))
             (kr (keyring-of gh hk acme)))
        (check-function OtpKeyring-next-hotp-counter!
          kr hk => 5
          kr hk => 6
          kr hk => 7)
        ;; The stored key holds the next counter and keeps its position;
        ;; the caller's key is unchanged.
        (check (OtpKeyring-list-keys kr)
               => [gh
                   (new-otp-key rfc-sha1-key issuer: "Example" account: "bob"
                                type: 'hotp counter: 8)
                   acme])
        (check (OtpKey-counter hk) => 5)
        (check (OtpKeyring-find-keys kr "example bob")
               => [(new-otp-key rfc-sha1-key issuer: "Example" account: "bob"
                                type: 'hotp counter: 8)])
        ;; Only the identity of the argument matters, not its counter or secret.
        (check (OtpKeyring-next-hotp-counter!
                kr (new-otp-key hello-key issuer: "Example" account: "bob" type: 'hotp))
               => 8)
        (check (OtpKey-counter (cadr (OtpKeyring-list-keys kr))) => 9)
        (check (OtpKey-secret (cadr (OtpKeyring-list-keys kr))) => rfc-sha1-key)))

    (test-case "next-hotp-counter!: errors"
      (let* ((hk (new-otp-key rfc-sha1-key issuer: "Example" account: "bob"
                              type: 'hotp counter: 5))
             (missing (new-otp-key rfc-sha1-key issuer: "Example" account: "carol"
                                   type: 'hotp))
             (kr (keyring-of gh hk)))
        (def (next key) (OtpKeyring-next-hotp-counter! kr key))
        (check-function next
          ;; absent identity
          missing =>! ContractViolation?
          (new-otp-key rfc-sha1-key issuer: "example" account: "bob" type: 'hotp)
          =>! ContractViolation?
          ;; stored key is totp
          gh =>! ContractViolation?
          ;; stored key is totp even though the argument is hotp
          (new-otp-key hello-key issuer: "github.com" account: "fare" type: 'hotp)
          =>! ContractViolation?)
        ;; Failures leave the keyring unchanged.
        (check (OtpKeyring-list-keys kr) => [gh hk])))

    (test-case "otp-keyring-register!: otpauth URIs, triples and mixtures"
      (def (register . items)
        (let (kr (new-memory-otp-keyring))
          (otp-keyring-register! kr items)
          (OtpKeyring-list-keys kr)))
      (check-function register
        ;; nothing
        => []
        ;; otpauth:// URIs, one item each; the scheme is case-insensitive
        "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        => [(new-otp-key hello-key issuer: "Example" account: "alice@google.com")]
        "otpauth://totp/alice@google.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        "OTPAUTH://hotp/Example:bob?secret=JBSWY3DPEHPK3PXP&counter=3"
        => [solo
            (new-otp-key hello-key issuer: "Example" account: "bob" type: 'hotp counter: 3)]
        ;; issuer account secret triples of strings
        "github.com" "fare" "JBSWY3DPEHPK3PXP"
        => [gh]
        "github.com" "fare" "JBSWY3DPEHPK3PXP"
        "GitLab" "fare@example.org" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        => [gh gl]
        ;; the empty issuer is kept as a string
        "" "fare" "JBSWY3DPEHPK3PXP"
        => [(new-otp-key hello-key issuer: "" account: "fare")]
        ;; keywords and symbols stand for their names
        github.com: fare: "JBSWY3DPEHPK3PXP"
        => [gh]
        'github.com 'fare 'JBSWY3DPEHPK3PXP
        => [gh]
        'GitLab "fare@example.org" GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ:
        => [gl]
        ;; lenient Base32 secrets: lowercase, spaces, padding
        "github.com" "fare" "jbsw y3dp ehpk 3pxp"
        => [gh]
        "x" "y" "AA======"
        => [(new-otp-key #u8(0) issuer: "x" account: "y")]
        ;; mixtures, in order
        "otpauth://totp/alice@google.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        github.com: "fare" 'JBSWY3DPEHPK3PXP
        "otpauth://totp/ACME%20Co:john.doe@email.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co"
        'Boxcom 'bob "jbswy3dpehpk3pxp"
        => [solo gh acme boxcom]
        ;; a repeated identity replaces the earlier one in place
        "github.com" "fare" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        'Boxcom 'bob "JBSWY3DPEHPK3PXP"
        github.com: fare: "JBSWY3DPEHPK3PXP"
        => [gh boxcom]))

    (test-case "otp-keyring-register!: adds after existing keys"
      (let (kr (keyring-of acme gh))
        (otp-keyring-register! kr ["GitLab" "fare@example.org" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                                   "github.com" "fare" "JBSW Y3DP EHPK 3PXP"])
        (check (OtpKeyring-list-keys kr) => [acme gh gl])))

    (test-case "otp-keyring-register!: errors"
      (def (register . items)
        (otp-keyring-register! (new-memory-otp-keyring) items))
      (check-function register
        ;; trailing groups of 1 or 2 non-otpauth items
        "github.com" =>! ContractViolation?
        "github.com" "fare" =>! ContractViolation?
        github.com: fare: =>! ContractViolation?
        "github.com" "fare" "JBSWY3DPEHPK3PXP" "GitLab" =>! ContractViolation?
        "github.com" "fare" "JBSWY3DPEHPK3PXP" "GitLab" "fare@example.org"
        =>! ContractViolation?
        "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP" "GitLab" "fare@example.org"
        =>! ContractViolation?
        ;; invalid otpauth URIs and secrets
        "otpauth://totp/alice" =>! ContractViolation?
        "otpauth://motp/alice?secret=JBSWY3DPEHPK3PXP" =>! ContractViolation?
        "github.com" "fare" "JBSWY3DP1HPK3PXP" =>! ContractViolation?
        ;; issuers cannot contain colons
        "git:hub" "fare" "JBSWY3DPEHPK3PXP" =>! ContractViolation?))

    (test-case "register-otp-keys registers into current-otp-keyring"
      (check (OtpKeyring? (current-otp-keyring)) => #t)
      (let ((kr (new-memory-otp-keyring))
            (global (current-otp-keyring))
            (global-keys (OtpKeyring-list-keys (current-otp-keyring))))
        (parameterize ((current-otp-keyring kr))
          (check (eq? (current-otp-keyring) kr) => #t)
          (register-otp-keys github.com: fare: "JBSWY3DPEHPK3PXP"
                             "otpauth://totp/alice@google.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
          (register-otp-keys)
          (register-otp-keys "GitLab" "fare@example.org" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
          (check (register-otp-keys "github.com" "fare") =>! ContractViolation?))
        (check (OtpKeyring-list-keys kr) => [gh solo gl])
        (check (eq? (current-otp-keyring) global) => #t)
        (check (OtpKeyring-list-keys (current-otp-keyring)) => global-keys)))

    (test-case "fresh keyrings are independent"
      (let ((kr1 (new-memory-otp-keyring))
            (kr2 (new-memory-otp-keyring)))
        (check (eq? kr1 kr2) => #f)
        (OtpKeyring-add-key! kr1 gh)
        (otp-keyring-register! kr2 ["GitLab" "fare@example.org" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"])
        (check-function OtpKeyring-list-keys
          kr1 => [gh]
          kr2 => [gl])
        (check (OtpKeyring-remove-key! kr2 "github.com" "fare") => #f)
        (check-function OtpKeyring-list-keys
          kr1 => [gh]
          (new-memory-otp-keyring) => [])))))
