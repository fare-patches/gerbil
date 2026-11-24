;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; OTP keyrings: named collections of otp-keys, and their registration from user scripts.
;;; Key Uri Format: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
;;; See keyring.md for the documentation.

(import :std/error
        :std/interface
        :std/text/glob
        ./core)
(export (interface-out OtpKeyring)
        new-memory-otp-keyring
        current-otp-keyring
        otp-keyring-register!
        register-otp-keys)

;; A collection of otp-keys, each identified by its (issuer, account) pair,
;; compared exactly: issuer #f (no issuer) is distinct from "", and case matters.
;; Keys are kept in insertion order; a key replacing one of the same identity
;; keeps the old key's position. The keyring shares its keys with its callers,
;; without copying them: callers must not mutate them or their secrets after
;; adding them.
(interface OtpKeyring
  ;; All keys, in insertion order, as a fresh list.
  (list-keys) => :list

  ;; The keys whose search text matches the glob pattern `*pattern*`, in
  ;; insertion order. Matching is case-insensitive (both sides are downcased);
  ;; `*` and `?` are wildcards, everything else literal. The search text is
  ;; "issuer account", or just the account for a key without issuer.
  (find-keys (pattern : :string)) => :list

  ;; Add key, replacing in place any key with the same identity.
  (add-key! (key : OtpKey)) => :void

  ;; Remove the key with this exact identity; return whether there was one.
  (remove-key! (issuer :? :string) (account : :string)) => :boolean

  ;; For the stored hotp key with the identity of key (its other fields are
  ;; ignored), return its counter and store in its place a copy whose counter
  ;; is one more. The caller's key is not modified. A missing identity or a
  ;; stored totp key raises ContractViolation and leaves the keyring unchanged.
  (next-hotp-counter! (key : OtpKey)) => :integer)

;; In-memory keyring: keys holds the keys at indexes [0, count) in insertion
;; order; index maps each identity (issuer . account), under equal?, to the
;; position of its key in keys. Lookup is O(1), removal O(n).
;; Not thread-safe: callers sharing one keyring between threads must serialize
;; access themselves.
(defstruct MemoryOtpKeyring
  ((keys  : :vector)
   (count : :fixnum)
   (index : HashTable))
  final: #t transparent: #f)

;; A fresh, empty in-memory keyring.
(def (new-memory-otp-keyring)
  => OtpKeyring
  (OtpKeyring (make-MemoryOtpKeyring (make-vector 8 #f) 0 (make-hash-table))))

;; The identity of a key in a keyring's index.
(def (otp-key-identity (key : OtpKey))
  => :pair
  (cons key.issuer key.account))

;; The text find-keys matches patterns against, downcased.
(def (otp-key-search-text (key : OtpKey))
  => :string
  (let (issuer key.issuer)
    (string-downcase
     (if issuer
       (string-append issuer " " key.account)
       key.account))))

(def (memory-otp-keyring-list-keys (self : MemoryOtpKeyring))
  => :list
  (let ((keys self.keys))
    (let loop ((i (fx1- self.count)) (result []))
      (if (fx>= i 0)
        (loop (fx1- i) (cons (vector-ref keys i) result))
        result))))

;; Fold the query once for case-insensitive substring matching.
(def (memory-otp-keyring-find-keys (self    : MemoryOtpKeyring)
                                   (pattern : :string))
  => :list
  (let ((glob (string-downcase (string-append "*" pattern "*")))
        (keys self.keys))
    (let loop ((i (fx1- self.count)) (result []))
      (if (fx>= i 0)
        (using (key (vector-ref keys i) :- OtpKey)
          (loop (fx1- i)
                (if (glob-match? glob (otp-key-search-text key))
                  (cons key result)
                  result)))
        result))))

;; Replace in place, or append, growing keys by doubling when full.
(def (memory-otp-keyring-add-key! (self : MemoryOtpKeyring)
                                  (key  : OtpKey))
  => :void
  (let* ((identity (otp-key-identity key))
         (position (hash-get self.index identity)))
    (if position
      (vector-set! self.keys position key)
      (let ((count self.count)
            (keys self.keys))
        (when (fx= count (vector-length keys))
          (let (new-keys (make-vector (fx* 2 count) #f))
            (subvector-move! keys 0 count new-keys 0)
            (set! self.keys new-keys)))
        (vector-set! self.keys count key)
        (hash-put! self.index identity count)
        (set! self.count (fx1+ count))))))

;; Shift the later keys down by one and renumber their index entries: O(n).
(def (memory-otp-keyring-remove-key! (self    : MemoryOtpKeyring)
                                     (issuer  :? :string)
                                     (account : :string))
  => :boolean
  (let* ((identity (cons issuer account))
         (position (hash-get self.index identity)))
    (and position
         (let ((keys self.keys)
               (last (fx1- self.count)))
           (hash-remove! self.index identity)
           (let loop ((i position))
             (when (fx< i last)
               (using (key (vector-ref keys (fx1+ i)) :- OtpKey)
                 (vector-set! keys i key)
                 (hash-put! self.index (otp-key-identity key) i)
                 (loop (fx1+ i)))))
           (vector-set! keys last #f)
           (set! self.count last)
           #t))))

(def (memory-otp-keyring-next-hotp-counter! (self : MemoryOtpKeyring)
                                            (key  : OtpKey))
  => :integer
  (let (position
          (or (hash-get self.index (otp-key-identity key))
              (raise-contract-violation OtpKeyring-next-hotp-counter! "No such OTP key"
                                        issuer: key.issuer
                                        account: key.account)))
    (using (stored (vector-ref self.keys position) :- OtpKey)
      (unless (eq? stored.type 'hotp)
        (raise-contract-violation OtpKeyring-next-hotp-counter! "Not an hotp key"
                                  issuer: stored.issuer
                                  account: stored.account
                                  type: stored.type))
      (let (counter stored.counter)
        ;; new-otp-key rejects a counter of 2^64, leaving the keyring unchanged.
        (vector-set! self.keys position
                     (new-otp-key stored.secret
                                  issuer: stored.issuer
                                  account: stored.account
                                  type: 'hotp
                                  algorithm: stored.algorithm
                                  digits: stored.digits
                                  period: stored.period
                                  counter: (+ counter 1)))
        counter))))

(implement OtpKeyring MemoryOtpKeyring
  (list-keys __memory-otp-keyring-list-keys)
  (find-keys __memory-otp-keyring-find-keys)
  (add-key! __memory-otp-keyring-add-key!)
  (remove-key! __memory-otp-keyring-remove-key!)
  (next-hotp-counter! __memory-otp-keyring-next-hotp-counter!))

;; The keyring register-otp-keys registers into; by default a process-wide
;; in-memory keyring, initially empty.
(def current-otp-keyring
  (make-parameter (new-memory-otp-keyring)))

;; Is item a string starting with "otpauth://", in any case?
(def (otpauth-item? item)
  => :boolean
  (and (string? item)
       (fx>= (string-length item) 10) ; (string-length "otpauth://")
       (string-ci=? (substring item 0 10) "otpauth://")))

;; The name of a string, symbol or keyword registration item.
(def (otp-registration-name item
                            (what : :string))
  => :string
  (cond
   ((string? item) item)
   ((symbol? item) (symbol->string item))
   ((keyword? item) (keyword->string item))
   (else
    (raise-bad-argument otp-keyring-register! "string, symbol or keyword"
                        what: what item: item))))

;; Parse registration items into otp-keys, in order: an otpauth:// URI string
;; is one key; any other item starts an issuer account secret triple.
(def (otp-registration-keys (items : :list))
  => :list
  (let loop ((items items) (keys []))
    (cond
     ((null? items) (reverse! keys))
     ((otpauth-item? (car items))
      (loop (cdr items) (cons (otpauth->otp-key (car items)) keys)))
     ((and (pair? (cdr items)) (pair? (cddr items)))
      (let ((issuer (otp-registration-name (car items) "issuer"))
            (account (otp-registration-name (cadr items) "account"))
            (secret (otp-registration-name (caddr items) "secret")))
        (loop (cdddr items)
              (cons (new-otp-key (decode-otp-secret otp-keyring-register! secret)
                                 issuer: issuer
                                 account: account)
                    keys))))
     (else
      (raise-contract-violation otp-keyring-register!
                                "Incomplete issuer account secret triple"
                                remaining: (length items))))))

;; Register items into keyring, in order. Each item is either an otpauth://
;; URI string (scheme in any case), or the start of a triple issuer account
;; secret, each a string, symbol or keyword standing for its name; the secret is
;; lenient Base32 and the other parameters take the new-otp-key defaults.
;; A key with an already present identity replaces it in place.
;; Atomic validation: all items are parsed and validated before any key is
;; added, so that an invalid item (ContractViolation) adds nothing.
(def (otp-keyring-register! (keyring : OtpKeyring)
                            (items   : :list))
  => :void
  (for-each (lambda ((key :- OtpKey)) (keyring.add-key! key))
            (otp-registration-keys items)))

;; Register items, as otp-keyring-register! does, into (current-otp-keyring).
;; Meant for user scripts: (register-otp-keys "gmail.com" "me" "abcd efgh ..." ...).
(def (register-otp-keys . items)
  => :void
  (otp-keyring-register! (current-otp-keyring) items))
