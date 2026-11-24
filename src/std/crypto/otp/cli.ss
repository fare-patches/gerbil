;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; OTP command-line entry points: keyring codes, otpauth:// URIs and one-off secrets.
;;; Key Uri Format: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
;;; RFC 4226 HOTP: https://www.rfc-editor.org/rfc/rfc4226
;;; RFC 6238 TOTP: https://www.rfc-editor.org/rfc/rfc6238
;;; See cli.md for the documentation.

(import :std/error
        :std/io
        (only-in :std/cli/multicall
                 register-entry-point
                 define-multicall-main)
        (only-in :std/cli/getopt
                 flag
                 option
                 multioption
                 argument
                 rest-arguments)
        (only-in :std/cli/print-exit
                 silent-exit)
        (only-in :std/encoding/hex
                 hex-decode)
        (only-in :std/list/list append-map delete-duplicates/hash)
        (only-in :std/text/parser/base
                 raise-parse-error)
        (only-in :std/text/parser/ll1
                 ll1
                 ll1-uint)
        (only-in :std/text/pregexp
                 pregexp
                 pregexp-match)
        (only-in :std/time/date string->date date->seconds seconds->date date->string Date-year)
        (only-in :std/time/time current-time-seconds)
        ./core
        ./keyring)
(export otp-code-command
        parse-otp-time
        ll1-otp-duration
        register-otp-entry-points!
        define-otp-main)

;;; Time and duration arguments

(def otp-natural-regexp
  (pregexp "^[0-9]+$"))

(def otp-hex-key-regexp
  (pregexp "^(?:[0-9a-fA-F]{2})+$"))

;; Parse a nonempty string of ASCII decimal digits; #f for anything else.
(def (parse-otp-natural (text : :string))
  => (Maybe :integer)
  (and (pregexp-match otp-natural-regexp text)
       (string->number text)))

(def otp-epoch-regexp (pregexp "^@(-?[0-9]+)$"))
(def otp-calendar-regexp
  (pregexp
   (string-append "^([0-9]{4}-[0-9]{2}-[0-9]{2})"
                  "(?:[Tt ]([0-9]{2}:[0-9]{2})(?::([0-5][0-9]))?"
                  "(?:(Z|z)|([+-])([0-9]{2}):?([0-9]{2}))?)?"
                  "( UTC)?$")))

(def (parse-otp-time (text : :string))
  => :integer
  (def (invalid reason) (raise-parse-error parse-otp-time reason text))
  (cond
   ((string=? text "now") (current-time-seconds))
   ((pregexp-match otp-epoch-regexp text) => (lambda (m) (string->number (cadr m))))
   ((pregexp-match otp-calendar-regexp text)
    => (lambda (m)
         (with ([whole day clock second z sign hours minutes utc] m)
           (when (and utc (or z sign))
             (invalid "TIME has two UTC designators"))
           (let* ((hour-offset (if hours (string->number hours) 0))
                  (min-offset (if minutes (string->number minutes) 0))
                  (stamp (string-append day " " (or clock "00:00") ":" (or second "00")))
                  (date (with-catch
                         (lambda (e) (if (contract-violation-error? e)
                                       (invalid "Invalid calendar date or time") (raise e)))
                         (lambda () (string->date stamp "%Y-%m-%d %H:%M:%S"))))
                  (seconds (date->seconds date))
                  (utc-date (seconds->date seconds)))
             ;; timegm may normalize an impossible day into the next month.
             ;; A round trip also detects dates outside the native time range.
             (unless (and (= (+ 1900 (Date-year utc-date)) (string->number (substring day 0 4)))
                          (equal? (date->string utc-date "%m-%d %H:%M:%S")
                                  (substring stamp 5 (string-length stamp))))
               (invalid "Invalid or unrepresentable calendar date"))
             (unless (and (< hour-offset 24) (< min-offset 60))
               (invalid "UTC offset outside the hour or minute range"))
             (- seconds (* (if (equal? sign "-") -1 1)
                           60 (+ (* 60 hour-offset) min-offset)))))))
   (else (invalid "TIME must be now, @SECONDS, or YYYY-MM-DD with optional time and UTC offset"))))

;; Parse a positive DURATION argument from reader as integer seconds:
;; decimal digits, optionally followed by a unit s (seconds, the default), m or h.
;; Raises ParseError on zero and on anything else.
(def (ll1-otp-duration (reader : BufferedReader))
  => :integer
  (let* ((n (ll1-uint reader))
         (unit (case (reader.peek-char-utf8)
                 ((#\s) (reader.read-char-utf8) 1)
                 ((#\m) (reader.read-char-utf8) 60)
                 ((#\h) (reader.read-char-utf8) 3600)
                 (else 1))))
    (if (positive? n)
      (* n unit)
      (abort! (raise-parse-error ll1-otp-duration
                                 "DURATION: expected a positive N, Ns, Nm or Nh" n)))))

;; Seconds of the whole DURATION argument text; raises ParseError.
(def (parse-otp-duration (text : :string))
  => :integer
  (ll1 ll1-otp-duration text))

;;; Keyring commands: keys, otpauth

;; The label shown for key: "issuer account", or the account alone.
(def (otp-key-label (key : OtpKey))
  => :string
  (let (issuer key.issuer)
    (if issuer
      (string-append issuer " " key.account)
      key.account)))

;; The code of key `offset` steps after time (totp) or after its counter (hotp).
(def (otp-key-code-at (key    : OtpKey)
                      (time   : :integer)
                      (offset : :fixnum))
  => :string
  (if (eq? key.type 'hotp)
    (hotp key.secret (+ key.counter offset)
          digits: key.digits
          algorithm: key.algorithm)
    (totp key.secret
          time: (+ time (* offset key.period))
          period: key.period
          digits: key.digits
          algorithm: key.algorithm)))

;; The codes of key at offsets 0..window, separated by spaces.
(def (otp-key-codes (key    : OtpKey)
                    (time   : :integer)
                    (window : :fixnum))
  => :string
  (let loop ((offset window) (codes []))
    (if (fx< offset 0)
      (string-join codes " ")
      (loop (fx1- offset) (cons (otp-key-code-at key time offset) codes)))))

;; Visit each matching key once, in pattern order and then keyring order. With no
;; match, print "No matching OTP key" to the current error port and return #f.
(def (for-each-matching-otp-key (patterns : :list)
                                (proc     : :procedure))
  => :boolean
  (def keyring (current-otp-keyring))
  (def (find-keys pattern) (OtpKeyring-find-keys keyring pattern))
  (let (keys (if (null? (cdr patterns))
               (find-keys (car patterns))
               (delete-duplicates/hash (append-map find-keys patterns)
                                       table: (make-hash-table-eq) from-end?: #t)))
    (if (null? keys)
      (begin
        (display "No matching OTP key\n" (current-error-port))
        #f)
      (begin
        (for-each (lambda ((key : OtpKey)) (proc key)) keys)
        #t))))

;; The keys command: print "CODE ... label" for each matching key, with codes
;; for offsets 0..window at time, in seconds since the epoch (default now).
;; hotp counters are not consumed.
(def (show-otp-keys (patterns    : :list)
                    (window-text :? :string)
                    (time        :? :integer))
  => :boolean
  (let ((window (if window-text
                  (let (window (parse-otp-natural window-text))
                    (if (fixnum? window)
                      window
                      (abort! (raise-bad-argument show-otp-keys "nonnegative window"
                                                  window: window-text))))
                  0))
        (time (or time (current-time-seconds))))
    (for-each-matching-otp-key
     patterns
     (lambda ((key :- OtpKey))
       (displayln (otp-key-codes key time window) " " (otp-key-label key))))))

;; The entry points return (void) on success and (values) on failure; see
;; silent-exit in :std/cli/print-exit.
;; NB: the keys entry point is untyped because typed keyword procedures with a
;; rest argument fail when called with both (duplicate keyword dispatch).

(def (otp-keys-command window: (window #f) time: (time #f) match: (matches []) . words)
  (let (patterns (if (and (pair? matches) (null? words))
                   matches
                   (append matches [(string-join words " ")])))
    (silent-exit (show-otp-keys patterns window time))))

(def (otp-otpauth-command . patterns)
  (silent-exit
   (for-each-matching-otp-key [(string-join patterns " ")] (lambda ((key :- OtpKey)) (displayln (otp-key->otpauth key))))))

;;; One-off code generation and verification

(def (parse-choice text choices)
  (or (let loop ((rest choices))
        (and (pair? rest)
             (if (string-ci=? text (symbol->string (car rest))) (car rest) (loop (cdr rest)))))
      (raise-bad-argument parse-choice "expected one of the listed choices" choices: choices)))

;; Parse the value of the counter, digits or window option.
(def (parse-otp-integer (option : :string)
                         (text   : :string)
                         (min    : :integer)
                         (max    : :integer))
  => :integer
  (let (value (parse-otp-natural text))
    (if (and value (<= min value max))
      (:- value :integer) ; non-#f here; the checker does not narrow through and
      (abort! (raise-bad-argument parse-otp-integer "integer option value in range"
                                  option: option value: text min: min max: max)))))

;; The first line of port, without a trailing CR; source names it for errors.
(def (read-otp-key-line (port   : :port)
                         (source : :string))
  => :string
  (let (line (read-line port))
    (when (eof-object? line)
      (raise-bad-argument read-otp-key "a KEY line" source: source))
    (let (len (string-length line))
      (if (and (fx> len 0) (char=? (string-ref line (fx1- len)) #\return))
        (substring line 0 (fx1- len))
        line))))

;; Decode the KEY argument: "-" is the first line of the current input port,
;; "@FILE" the first line of FILE, anything else the key itself; then hex
;; (an even number of hex digits) or, with base32?, lenient Base32.
;; Errors report lengths, never key characters.
(def (read-otp-key (key     : :string)
                    (base32? : :boolean))
  => :u8vector
  (let* ((text (cond
                ((string=? key "-")
                 (read-otp-key-line (current-input-port) "standard input"))
                ((string-prefix? "@" key)
                 (let (path (substring key 1 (string-length key)))
                   (call-with-input-file path (lambda (port) (read-otp-key-line port path)))))
                (else key)))
         (secret (cond
                  (base32?
                   (decode-otp-secret read-otp-key text))
                  ((pregexp-match otp-hex-key-regexp text)
                   (hex-decode text))
                  (else
                   (raise-bad-argument read-otp-key "hex KEY with an even number of digits"
                                       length: (string-length text))))))
    (when (fxzero? (u8vector-length secret))
      (raise-bad-argument read-otp-key "nonempty KEY"))
    secret))

(def (otp-code-command (key : :string)
                       (otp :? :string := #f)
                       mode:     (mode     : :symbol   := 'totp)
                       algorithm: (algorithm : :symbol := 'sha1)
                       encoding: (encoding : :symbol   := 'base32)
                       counter:  (counter  : :integer  := 0)
                       step:     (step     : :integer  := 30)
                       start:    (start    : :integer  := 0)
                       now:      (now      :? :integer := #f)
                       digits:   (digits   : :fixnum   := 6)
                       window:   (window   : :fixnum   := 0)
                       verbose:  (verbose? : :boolean  := #f))
  (unless (memq mode '(hotp totp))
    (raise-bad-argument otp-code-command "mode hotp or totp" mode: mode))
  (unless (memq encoding '(hex base32))
    (raise-bad-argument otp-code-command "encoding hex or base32" encoding: encoding))
  (unless (<= 0 window (- (expt 2 31) 1))
    (raise-bad-argument otp-code-command "window in [0, 2^31)" window: window))
  (let* ((secret (read-otp-key key (eq? encoding 'base32)))
         (totp? (eq? mode 'totp))
         (time (or now (current-time-seconds)))
         (first (if totp? (totp-counter time period: step start: start) counter)))
    (when verbose?
      (displayln "Mode: " (if totp?
                            (string-append "TOTP " (string-upcase (symbol->string algorithm)))
                            "HOTP"))
      (unless (or totp? (eq? algorithm 'sha1))
        (displayln "Algorithm: " (string-upcase (symbol->string algorithm))))
      (displayln "Key length: " (u8vector-length secret) " bytes")
      (displayln "Digits: " digits)
      (displayln "Window size: " window)
      (when totp?
        (displayln "Step size (seconds): " step)
        (displayln "Start time: " start)
        (displayln "Current time: " time))
      (displayln (if totp? "Counter: " "Start counter: ") first)
      (newline))
    (if otp
      (let (match (if totp?
                    (totp-validate secret otp time: time period: step start: start
                                   window: window digits: digits algorithm: algorithm)
                    (hotp-validate secret otp counter: counter window: window
                                   digits: digits algorithm: algorithm)))
        (when match (displayln match))
        (silent-exit match))
      (let loop ((offset 0))
        (when (fx<= offset window)
          (displayln (hotp secret (+ first offset) digits: digits algorithm: algorithm))
          (loop (fx1+ offset)))))))

;;; Registration

;; Register the keys, otpauth, generate and verify entry points in the global
;; :std/cli/multicall registry, replacing any entry points of the same names.
;; Importing this module registers nothing, so that library users can compute
;; codes without changing the command-line dispatch of their program;
;; define-otp-main calls this.
(def (register-otp-entry-points!)
  => :void
  (register-entry-point otp-keys-command id: 'otp-keys-command name: "keys"
   help: "Show the codes of the keys matching the patterns (glob, case-insensitive)"
   getopt: [(multioption 'match "-m" "--match"
                    help: "match a glob (repeatable, in display order)")
            (option 'window "-w" "--window" help: "also show the next N codes")
            (option 'time "-N" "--time" parse: parse-otp-time
                    help: "time: now, @SECONDS or a date-time (UTC by default)")
            (rest-arguments 'patterns help: "key patterns, joined with spaces")])
  (register-entry-point otp-otpauth-command id: 'otp-otpauth-command name: "otpauth"
   help: "Show the otpauth:// URIs of the keys matching the patterns"
   getopt: [(rest-arguments 'patterns help: "key patterns, joined with spaces")])

  (let (common
        [(option 'mode #f "--mode" default: 'totp
                 parse: (cut parse-choice <> '(hotp totp)) help: "hotp or totp (default)")
         (option 'algorithm #f "--hash" default: 'sha1
                 parse: (cut parse-choice <> '(sha1 sha256 sha512)) help: "HMAC digest")
         (option 'encoding #f "--encoding" default: 'base32
                 parse: (cut parse-choice <> '(base32 hex)) help: "base32 (default) or hex")
         (option 'counter #f "--counter" default: 0
                 parse: (cut parse-otp-integer "--counter" <> 0 (- (expt 2 64) 1)))
         (option 'step #f "--period" default: 30 parse: parse-otp-duration)
         (option 'start #f "--start" default: 0 parse: parse-otp-time)
         (option 'now #f "--time" parse: parse-otp-time)
         (option 'digits #f "--digits" default: 6 parse: (cut parse-otp-integer "--digits" <> 6 10))
         (option 'window #f "--window" default: 0
                 parse: (cut parse-otp-integer "--window" <> 0 (- (expt 2 31) 1)))
         (flag 'verbose #f "--verbose" help: "print parameters before the result")
         (argument 'key help: "secret, - for stdin or @FILE")])
    (register-entry-point otp-code-command name: "generate"
      help: "Generate one or more codes for a supplied secret" getopt: common)
    (register-entry-point otp-code-command name: "verify"
      help: "Print the matching HOTP counter or TOTP step offset"
      getopt: (append common [(argument 'otp help: "code to verify")])))
  (void))

;;; Main

;; Register the OTP entry points (see register-otp-entry-points!) and define
;; main as a multicall main (see define-multicall-main in :std/cli/multicall)
;; whose default entry point is keys, so that `prog` shows every code and
;; `prog PATTERN ...` the codes of the matching keys.
(defrules define-otp-main ()
  ((_ ctx) (begin
             (register-otp-entry-points!)
             (define-multicall-main ctx default: 'keys fallback: #t)))
  ((d) (d d)))
