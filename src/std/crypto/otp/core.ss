;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HOTP and TOTP one-time passwords, and otpauth:// key URIs.
;;; RFC 4226 HOTP: https://www.rfc-editor.org/rfc/rfc4226
;;; RFC 6238 TOTP: https://www.rfc-editor.org/rfc/rfc6238
;;; RFC 2104 HMAC: https://www.rfc-editor.org/rfc/rfc2104
;;; RFC 4648 §6 Base32: https://www.rfc-editor.org/rfc/rfc4648#section-6
;;; RFC 3986 URI: https://www.rfc-editor.org/rfc/rfc3986
;;; Key Uri Format: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
;;; See core.md for the documentation.

(import :std/error
        :std/crypto/hmac
        :std/encoding/base32
        :std/net/uri
        (only-in :std/time/time
                 current-time-seconds)
        (only-in :std/vector/u8vector
                 &u8vector-uint-ref/be
                 &u8vector-uint-set!/be))
(export hotp
        totp-counter
        totp
        hotp-validate
        totp-validate
        OtpKey
        OtpKey?
        OtpKey-issuer
        OtpKey-account
        OtpKey-secret
        OtpKey-type
        OtpKey-algorithm
        OtpKey-digits
        OtpKey-period
        OtpKey-counter
        new-otp-key
        decode-otp-secret
        otp-key-code
        otpauth->otp-key
        otp-key->otpauth)

;; An OTP key as found in an otpauth:// URI. A key shares its secret u8vector
;; with whoever made it, without copying it; nobody must mutate it afterwards. Transparent for equal?, which compares keys
;; field by field, secret included; printing omits the secret.
;; issuer: #f or a string without a colon; account: label account name;
;; type: 'totp or 'hotp; algorithm: 'sha1, 'sha256 or 'sha512; digits: 6..10;
;; period: positive TOTP step in seconds (kept but unused for hotp);
;; counter: HOTP moving factor in [0, 2^64) (kept but unused for totp).
(defstruct OtpKey
  ((issuer    :? :string)
   (account   : :string)
   (secret    : :u8vector)
   (type      : :symbol)
   (algorithm : :symbol)
   (digits    : :fixnum)
   (period    : :integer)
   (counter   : :integer))
  transparent: #t
  constructor: :init!
  print: (issuer account type algorithm digits period counter)
  final: #t)

;; HOTP counters are 8-byte unsigned big-endian integers (RFC 4226 §5.1).
(def otp-counter-limit (expt 2 64))

;; Argument checks shared by the public procedures; `where` names the caller.
(defrule (check-otp-counter where counter)
  (unless (and (<= 0 counter) (< counter otp-counter-limit))
    (raise-bad-argument where "counter in [0, 2^64)" counter: counter)))

(defrule (check-otp-digits where digits)
  (unless (fx<= 6 digits 10)
    (raise-bad-argument where "digits between 6 and 10" digits: digits)))

(defrule (check-otp-algorithm where algorithm)
  (unless (memq algorithm '(sha1 sha256 sha512))
    (raise-bad-argument where "algorithm 'sha1, 'sha256 or 'sha512" algorithm: algorithm)))

(defrule (check-otp-period where period)
  (unless (positive? period)
    (raise-bad-argument where "positive period" period: period)))

(defrule (check-otp-window where window)
  (unless (fx>= window 0)
    (raise-bad-argument where "nonnegative window" window: window)))

(defrule (check-otp-time where time)
  (unless (or (exact? time) (finite? time))
    (raise-bad-argument where "finite time" time: time)))

;; HMAC of message under key; callers validate algorithm.
(def (otp-hmac (key       : :u8vector)
               (message   : :u8vector)
               (algorithm : :symbol))
  => :u8vector
  (case algorithm
    ((sha1) (hmac-sha1 key message))
    ((sha256) (hmac-sha256 key message))
    (else (hmac-sha512 key message))))

;; RFC 4226 §5.3 dynamic truncation: the low nibble of the last MAC byte is an
;; offset; the four bytes there, big-endian with the top bit cleared, form a
;; 31-bit integer. Using the last byte makes it work for SHA-256/512 MACs too.
(def (otp-truncate (mac : :u8vector))
  => :fixnum
  (let (offset (fxand (u8vector-ref mac (fx1- (u8vector-length mac))) #x0f))
    (fxand (&u8vector-uint-ref/be mac offset 4) #x7fffffff)))

;; Truncated HOTP value of counter, before reduction modulo 10^digits.
;; buffer is an 8-byte scratch u8vector, reused across a validation window.
(def (hotp-value (key       : :u8vector)
                 (counter   : :integer)
                 (algorithm : :symbol)
                 (buffer    : :u8vector))
  => :fixnum
  (&u8vector-uint-set!/be buffer 0 counter 8)
  (otp-truncate (otp-hmac key buffer algorithm)))

;; The last `digits` decimal digits of value, zero-padded: value mod 10^digits.
(def (otp-code-string (value  : :fixnum)
                      (digits : :fixnum))
  => :string
  (let (out (make-string digits #\0))
    (let loop ((i (fx1- digits)) (value value))
      (if (and (fx>= i 0) (fx> value 0))
        (begin
          (string-set! out i (integer->char (fx+ 48 (fxremainder value 10))))
          (loop (fx1- i) (fxquotient value 10)))
        out))))

;; The value of a code of exactly `digits` ASCII decimal digits, or -1.
;; Codes are user input, not secrets; returning early on bad syntax is fine.
(def (otp-code-value (code   : :string)
                     (digits : :fixnum))
  => :fixnum
  (if (fx= (string-length code) digits)
    (let loop ((i 0) (value 0))
      (if (fx< i digits)
        (let (d (fx- (char->integer (string-ref code i)) 48))
          (if (and (fx>= d 0) (fx<= d 9))
            (loop (fx1+ i) (fx+ (fx* value 10) d))
            -1))
        value))
    -1))

;; The TOTP time step floor((time - start) / period); exact even for real time.
;; Flooring time first is equivalent because start and period are integers.
(def (otp-time-step (time   : :real)
                    (start  : :integer)
                    (period : :integer))
  => :integer
  (floor-quotient (- (if (exact-integer? time) time (exact (floor time))) start)
                  period))

;; Compute the RFC 4226 HOTP code of key at counter, as `digits` decimal digits.
;; counter is an exact integer in [0, 2^64); digits in 6..10; algorithm is
;; 'sha1 (RFC 4226), 'sha256 or 'sha512 (RFC 6238). Bad values raise ContractViolation.
(def (hotp (key     : :u8vector)
           (counter : :integer)
           digits:    (digits    : :fixnum := 6)
           algorithm: (algorithm : :symbol := 'sha1))
  => :string
  (check-otp-counter hotp counter)
  (check-otp-digits hotp digits)
  (check-otp-algorithm hotp algorithm)
  (otp-code-string (hotp-value key counter algorithm (make-u8vector 8)) digits))

;; The RFC 6238 time step T = floor((time - start) / period) as an exact integer.
;; time may be any finite real (seconds since the Unix epoch); it is negative
;; before start. period is a positive integer, start an integer.
(def (totp-counter (time : :real)
                   period: (period : :integer := 30)
                   start:  (start  : :integer := 0))
  => :integer
  (check-otp-time totp-counter time)
  (check-otp-period totp-counter period)
  (otp-time-step time start period))

;; Compute the RFC 6238 TOTP code of key at time (default: now), i.e. the HOTP
;; code at the time step (totp-counter time). A time step outside [0, 2^64)
;; raises ContractViolation, as do bad digits, algorithm, period or time.
(def (totp (key : :u8vector)
           time:      (time      : :real    := (current-time-seconds))
           period:    (period    : :integer := 30)
           start:     (start     : :integer := 0)
           digits:    (digits    : :fixnum  := 6)
           algorithm: (algorithm : :symbol  := 'sha1))
  => :string
  (check-otp-time totp time)
  (check-otp-period totp period)
  (check-otp-digits totp digits)
  (check-otp-algorithm totp algorithm)
  (let (step (otp-time-step time start period))
    (unless (and (<= 0 step) (< step otp-counter-limit))
      (raise-bad-argument totp "time step in [0, 2^64)"
                          step: step time: time start: start period: period))
    (otp-code-string (hotp-value key step algorithm (make-u8vector 8)) digits)))

;; Validate an HOTP code against counters counter, counter+1, ..., counter+window
;; (stopping below 2^64), in that order. Return the first matching counter, or #f.
;; A code that is not exactly `digits` decimal digits never matches. The caller
;; must persist the returned counter + 1 as the next counter to prevent replay.
;; Codes are compared as integers, not character by character.
(def (hotp-validate (key  : :u8vector)
                    (code : :string)
                    counter:   (counter   : :integer := 0)
                    window:    (window    : :fixnum  := 0)
                    digits:    (digits    : :fixnum  := 6)
                    algorithm: (algorithm : :symbol  := 'sha1))
  => (Maybe :integer)
  (check-otp-counter hotp-validate counter)
  (check-otp-window hotp-validate window)
  (check-otp-digits hotp-validate digits)
  (check-otp-algorithm hotp-validate algorithm)
  (let (expected (otp-code-value code digits))
    (and (fx>= expected 0)
         (let ((modulus (expt 10 digits))
               (last (min (+ counter window) (- otp-counter-limit 1)))
               (buffer (make-u8vector 8)))
           (let loop ((c counter))
             (cond
              ((> c last) #f)
              ((fx= (fxremainder (hotp-value key c algorithm buffer) modulus) expected) c)
              (else (loop (+ c 1)))))))))

;; Validate a TOTP code at time (default: now) against time steps T+offset for
;; offsets 0, -1, +1, -2, +2, ..., -window, +window, in that order, where
;; T = (totp-counter time period: period start: start). Steps outside
;; [0, 2^64) are skipped. Return the first matching offset, or #f.
;; Codes are compared as integers, not character by character.
;; Replay protection (remembering the last accepted step) is the caller's job.
(def (totp-validate (key  : :u8vector)
                    (code : :string)
                    time:      (time      : :real    := (current-time-seconds))
                    period:    (period    : :integer := 30)
                    start:     (start     : :integer := 0)
                    window:    (window    : :fixnum  := 0)
                    digits:    (digits    : :fixnum  := 6)
                    algorithm: (algorithm : :symbol  := 'sha1))
  => (Maybe :fixnum)
  (check-otp-time totp-validate time)
  (check-otp-period totp-validate period)
  (check-otp-window totp-validate window)
  (check-otp-digits totp-validate digits)
  (check-otp-algorithm totp-validate algorithm)
  (let (expected (otp-code-value code digits))
    (and (fx>= expected 0)
         (let ((step (otp-time-step time start period))
               (modulus (expt 10 digits))
               (buffer (make-u8vector 8)))
           (def (match? offset)
             (let (c (+ step offset))
               (and (<= 0 c)
                    (< c otp-counter-limit)
                    (fx= (fxremainder (hotp-value key c algorithm buffer) modulus)
                         expected))))
           (let loop ((offset 0))
             (cond
              ((fx> offset window) #f)
              ((match? (fx- offset)) (fx- offset))
              ((and (fx> offset 0) (match? offset)) offset)
              (else (loop (fx1+ offset)))))))))

(defmethod {:init! OtpKey}
  (lambda (self (issuer :? :string) (account : :string) (secret : :u8vector)
                (type : :symbol) (algorithm : :symbol) (digits : :fixnum)
                (period : :integer) (counter : :integer))
    (when (fxzero? (u8vector-length secret))
      (raise-bad-argument make-OtpKey "nonempty secret"))
    (when (and issuer (string-index issuer #\:))
      (raise-bad-argument make-OtpKey "issuer without a colon" issuer: issuer))
    (when (and (not issuer) (string-index account #\:))
      (raise-bad-argument make-OtpKey "account without a colon when issuer is absent"
                          account: account))
    (when (and issuer (positive? (string-length account))
               (char=? (string-ref account 0) #\space))
      (raise-bad-argument make-OtpKey "account without a leading space when issuer is present"
                          account: account))
    (unless (memq type '(totp hotp))
      (raise-bad-argument make-OtpKey "type 'totp or 'hotp" type: type))
    (check-otp-algorithm make-OtpKey algorithm)
    (check-otp-digits make-OtpKey digits)
    (check-otp-period make-OtpKey period)
    (check-otp-counter make-OtpKey counter)
    (set! self.issuer issuer)
    (set! self.account account)
    (set! self.secret secret)
    (set! self.type type)
    (set! self.algorithm algorithm)
    (set! self.digits digits)
    (set! self.period period)
    (set! self.counter counter)))

;; Construct a validated OtpKey. secret must be nonempty, as otpauth->otp-key
;; requires; issuer must not contain a colon (it is the
;; label prefix of otpauth:// URIs); type is 'totp or 'hotp; algorithm 'sha1,
;; 'sha256 or 'sha512; digits 6..10; period positive; counter in [0, 2^64).
;; Bad values raise ContractViolation. The key shares secret, without copying it.
(def (new-otp-key (secret : :u8vector)
                  issuer:    (issuer    :? :string := #f)
                  account:   (account   : :string  := "")
                  type:      (type      : :symbol  := 'totp)
                  algorithm: (algorithm : :symbol  := 'sha1)
                  digits:    (digits    : :fixnum  := 6)
                  period:    (period    : :integer := 30)
                  counter:   (counter   : :integer := 0))
  => OtpKey
  (make-OtpKey issuer account secret type algorithm digits period counter))

;; The current code of key: for 'hotp keys, the HOTP code at the key's counter
;; (time is ignored; the caller advances the counter); for 'totp keys, the TOTP
;; code at time (default: now) with the key's period and start 0.
(def (otp-key-code (key : OtpKey)
                   time: (time : :real := (current-time-seconds)))
  => :string
  (if (eq? key.type 'hotp)
    (hotp key.secret key.counter
          digits: key.digits
          algorithm: key.algorithm)
    (totp key.secret
          time: time
          period: key.period
          digits: key.digits
          algorithm: key.algorithm)))

;; Is char an ASCII hexadecimal digit?
(def (hex-char? (char : :char))
  => :boolean
  (or (and (char>=? char #\0) (char<=? char #\9))
      (and (char>=? char #\a) (char<=? char #\f))
      (and (char>=? char #\A) (char<=? char #\F))))

;; Percent-decode uri[start:end] after checking every % escape, so that
;; malformed input raises without the (possibly secret) string as an irritant.
;; '+' is not a space. what names the URI component for diagnostics.
(def (otpauth-decode (uri   : :string)
                     (start : :fixnum)
                     (end   : :fixnum)
                     (what  : :string))
  => :string
  (let loop ((i start))
    (when (fx< i end)
      (if (char=? (string-ref uri i) #\%)
        (if (and (fx<= (fx+ i 3) end)
                 (hex-char? (string-ref uri (fx+ i 1)))
                 (hex-char? (string-ref uri (fx+ i 2))))
          (loop (fx+ i 3))
          (raise-contract-violation otpauth->otp-key "Malformed percent-encoding"
                                    component: what index: i))
        (loop (fx1+ i)))))
  (uri-decode (substring uri start end)))

;; Parse a nonempty string of ASCII decimal digits as an exact integer.
;; Unlike string->number, reject signs, radix prefixes, decimals and exponents.
(def (otpauth-integer (name  : :string)
                      (value : :string))
  => :integer
  (let (len (string-length value))
    (unless (fx> len 0)
      (raise-contract-violation otpauth->otp-key "Empty integer parameter"
                                parameter: name))
    (let loop ((i 0) (n 0))
      (if (fx< i len)
        (let (d (fx- (char->integer (string-ref value i)) 48))
          (unless (and (fx>= d 0) (fx<= d 9))
            (raise-contract-violation otpauth->otp-key "Invalid integer parameter"
                                      parameter: name value: value))
          (loop (fx1+ i) (+ (* n 10) d)))
        n))))

;; Decode the Base32 secret parameter with base32-decode-lenient. Failures
;; are re-raised with the decoder's reason and the length only: the decoder's
;; irritants may include characters of the secret.
(def (decode-otp-secret where (value : :string))
  => :u8vector
  (let (secret (with-catch
                (lambda (e)
                  (if (ContractViolation? e)
                    (let (irritants (Error-irritants e))
                      (raise-contract-violation where "Invalid Base32 secret"
                                                reason: (and (pair? irritants)
                                                             (pgetq contract: (cdr irritants)))
                                                length: (string-length value)))
                    (raise e)))
                (lambda () (base32-decode-lenient value))))
    (when (fxzero? (u8vector-length secret))
      (raise-contract-violation where "Empty Base32 secret"))
    secret))

;; Parse an otpauth:// Key Uri Format URI into a validated OtpKey.
;; otpauth://TYPE/LABEL?PARAMETERS[#fragment]: scheme and TYPE (totp|hotp) are
;; case-insensitive. LABEL is percent-decoded, then split at its first colon
;; into an issuer prefix and an account (leading spaces of the account are
;; dropped); without a colon it is all account. PARAMETERS split at '&' and
;; each at its first '=', then both sides are percent-decoded; names are
;; case-sensitive, unknown ones ignored, and a repeated one keeps its last value.
;; secret (lenient Base32, nonempty) is required; issuer overrides the label
;; prefix; algorithm SHA1|SHA256|SHA512 (any case, default SHA1); digits 6..10
;; (default 6); period positive (default 30); counter in [0, 2^64), required for
;; hotp and ignored for totp. Malformed or invalid input raises ContractViolation.
(def (otpauth->otp-key (uri : :string))
  => OtpKey
  (let* ((len (string-length uri))
         (prefix-end 10)) ; (string-length "otpauth://")
    (unless (and (fx>= len prefix-end)
                 (string-ci=? (substring uri 0 prefix-end) "otpauth://"))
      (raise-contract-violation otpauth->otp-key "Not an otpauth:// URI"))
    (let* ((slash (or (string-index uri #\/ prefix-end)
                      (raise-contract-violation otpauth->otp-key "Missing otpauth label")))
           (type-name (substring uri prefix-end slash))
           (type (cond
                  ((string-ci=? type-name "totp") 'totp)
                  ((string-ci=? type-name "hotp") 'hotp)
                  (else
                   (raise-contract-violation otpauth->otp-key "Unsupported OTP type"
                                             type: type-name))))
           (end (or (string-index uri #\# slash) len))
           (query (or (string-index uri #\? slash end) end))
           (label (otpauth-decode uri (fx1+ slash) query "label"))
           (secret #f)
           (issuer #f)
           (algorithm #f)
           (digits #f)
           (period #f)
           (counter #f))
      ;; Collect the parameters of interest as decoded strings.
      (let loop ((i (fx1+ query)))
        (when (fx< i end)
          (let* ((amp (or (string-index uri #\& i end) end))
                 (equals (string-index uri #\= i amp))
                 (name (otpauth-decode uri i (or equals amp) "parameter name"))
                 (value (if equals (otpauth-decode uri (fx1+ equals) amp name) "")))
            (cond
             ((string=? name "secret") (set! secret value))
             ((string=? name "issuer") (set! issuer value))
             ((string=? name "algorithm") (set! algorithm value))
             ((string=? name "digits") (set! digits value))
             ((string=? name "period") (set! period value))
             ((string=? name "counter") (set! counter value)))
            (loop (fx1+ amp)))))
      (unless secret
        (raise-contract-violation otpauth->otp-key "Missing secret parameter"))
      (let* ((colon (string-index label #\:))
             (account (if colon
                        (let skip ((i (fx1+ colon)))
                          (if (and (fx< i (string-length label))
                                   (char=? (string-ref label i) #\space))
                            (skip (fx1+ i))
                            (substring label i (string-length label))))
                        label))
             ;; The issuer parameter silently wins over a different label prefix.
             (issuer (or issuer (and colon (substring label 0 colon))))
             (algorithm (cond
                         ((not algorithm) 'sha1)
                         ((string-ci=? algorithm "SHA1") 'sha1)
                         ((string-ci=? algorithm "SHA256") 'sha256)
                         ((string-ci=? algorithm "SHA512") 'sha512)
                         (else
                          (raise-contract-violation otpauth->otp-key "Unsupported algorithm"
                                                    algorithm: algorithm))))
             (digits (if digits (otpauth-integer "digits" digits) 6))
             (period (if period (otpauth-integer "period" period) 30))
             (counter (cond
                       ((eq? type 'totp) 0)
                       (counter (otpauth-integer "counter" counter))
                       (else
                        (raise-contract-violation otpauth->otp-key
                                                  "Missing counter parameter for hotp")))))
        (when (and issuer (string-index issuer #\:))
          (raise-contract-violation otpauth->otp-key "Issuer contains a colon"
                                    issuer: issuer))
        (unless (<= 6 digits 10)
          (raise-contract-violation otpauth->otp-key "Digits not between 6 and 10"
                                    digits: digits))
        (unless (positive? period)
          (raise-contract-violation otpauth->otp-key "Period not positive"
                                    period: period))
        (unless (< counter otp-counter-limit)
          (raise-contract-violation otpauth->otp-key "Counter not below 2^64"
                                    counter: counter))
        (make-OtpKey issuer account (decode-otp-secret otpauth->otp-key secret)
                      type algorithm digits period counter)))))

;; Emit the canonical otpauth:// URI of key: label "issuer:account" (or just
;; account) with each part percent-encoded (RFC 3986 unreserved characters
;; kept), then secret (unpadded uppercase Base32), issuer if any, algorithm
;; (uppercase), digits, and period for totp or counter for hotp.
(def (otp-key->otpauth (key : OtpKey))
  => :string
  (let* ((issuer key.issuer)
         (encoded-issuer (and issuer (uri-encode issuer)))
         (hotp? (eq? key.type 'hotp)))
    (string-append
     (if hotp? "otpauth://hotp/" "otpauth://totp/")
     (if encoded-issuer (string-append encoded-issuer ":") "")
     (uri-encode key.account)
     "?secret=" (base32-encode key.secret padding: #f)
     (if encoded-issuer (string-append "&issuer=" encoded-issuer) "")
     (case key.algorithm
       ((sha1) "&algorithm=SHA1")
       ((sha256) "&algorithm=SHA256")
       (else "&algorithm=SHA512"))
     "&digits=" (number->string key.digits)
     (if hotp?
       (string-append "&counter=" (number->string key.counter))
       (string-append "&period=" (number->string key.period))))))
