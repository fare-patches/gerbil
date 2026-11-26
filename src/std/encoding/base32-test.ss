;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; RFC 4648 Base32 codec tests.

(import :std/test
        :std/error
        ./base32)
(export base32-test)

(def base32-test
  (test-suite "test :std/encoding/base32"
    (test-case "RFC 4648 vectors and case/padding options"
      (for-each
       (lambda (bytes padded unpadded)
         (check (base32-encode bytes) => padded)
         (check (base32-encode bytes padding: #f) => unpadded)
         (check (base32-encode bytes lowercase: #t) => (string-downcase padded))
         (check (base32-encode bytes padding: #f lowercase: #t) => (string-downcase unpadded))
         (check (base32-decode padded) => bytes)
         (check (base32-decode (string-downcase padded)) => bytes)
         (check (base32-decode padded no-padding: #t) => bytes)
         (check (base32-decode (string-downcase unpadded) no-padding: #t) => bytes)
         (check-function base32-decode-lenient
           padded => bytes
           unpadded => bytes
           (string-downcase padded) => bytes
           (string-downcase unpadded) => bytes
           (string-append padded "========") =>! ContractViolation?)
         (unless (= (string-length padded) (string-length unpadded))
           (check-exception (base32-decode unpadded) ContractViolation?)))
       (list #u8() #u8(102) #u8(102 111) #u8(102 111 111)
             #u8(102 111 111 98) #u8(102 111 111 98 97) #u8(102 111 111 98 97 114))
       '("" "MY======" "MZXQ====" "MZXW6===" "MZXW6YQ=" "MZXW6YTB" "MZXW6YTBOI======")
       '("" "MY" "MZXQ" "MZXW6" "MZXW6YQ" "MZXW6YTB" "MZXW6YTBOI"))
      (check (base32-decode "mZxW6yTb") => #u8(102 111 111 98 97)))
    (test-case "binary zeros and every byte value"
      (check (base32-encode #u8(0 0 0 0 0)) => "AAAAAAAA")
      (check (base32-encode #u8(255)) => "74======")
      (check (base32-decode "AAAAAAAB") => #u8(0 0 0 0 1))
      (let (bytes (make-u8vector 256))
        (let loop ((i 0))
          (when (< i 256)
            (u8vector-set! bytes i i)
            (loop (+ i 1))))
        (check (base32-decode (base32-encode bytes)) => bytes)))
    (test-case "deterministic roundtrips across all residues"
      (def (group str sep)
        (let loop ((i 0) (acc []))
          (if (< i (string-length str))
            (loop (+ i 1) (cons (string-ref str i)
                                (if (and (> i 0) (zero? (modulo i 4))) (cons sep acc) acc)))
            (list->string (reverse acc)))))
      (let sizes ((n 0))
        (when (<= n 512)
          (let (bytes (make-u8vector n))
            (let fill ((i 0))
              (when (< i n)
                (u8vector-set! bytes i (modulo (+ (* i i 17) (* n 31) i) 256))
                (fill (+ i 1))))
            (let ((padded (base32-encode bytes))
                  (bare (base32-encode bytes padding: #f lowercase: #t)))
              (check (string-length padded) => (* 8 (quotient (+ n 4) 5)))
              (check (string-length bare) => (quotient (+ (* n 8) 4) 5))
              (check (base32-decode padded) => bytes)
              (check (base32-decode padded no-padding: #t) => bytes)
              (check (base32-decode bare no-padding: #t) => bytes)
              (check-function base32-decode-lenient
                padded => bytes
                bare => bytes
                (group bare #\space) => bytes
                (group padded #\-) => bytes)))
          (sizes (+ n 1)))))
    (test-case "invalid lengths, padding, alphabet and pad bits"
      (for-each
       (lambda (str)
         (check-exception (base32-decode str) ContractViolation?)
         (check-exception (base32-decode str no-padding: #t) ContractViolation?))
       '("A" "AAA" "AAAAAA" "AAAAAAAAA" "AAAAAAAAAAA" "AAAAAAAAAAAAAA"
         "A=======" "AAA=====" "AAAAAA==" "=" "========"
         "MY=" "MY=====" "MY=======" "MY==============" "MZXW6YTB="
         "M=AAAAAA" "MY======MY======" "MY=====A" "=Y======"
         "M0======" "M1======" "M8======" "M9======" "M+======" "M/======"
         "M-======" "M_======" "M ======" "M\n======" "M\t======" "M\x00;======"
         "M\x100;======" "MZ======" "MZXR====" "MZXW7===" "MZXW6YR="
         "MZ" "MZXR" "MZXW7" "MZXW6YR"))
      ;; Each possible nonzero low-bit pattern is invalid in every partial group.
      (for-each
       (lambda (prefix unused)
         (let loop ((value 1))
           (when (< value (expt 2 unused))
             (let* ((str (string-append prefix
                                       (string (string-ref "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" value))))
                    (padded (string-append str (make-string (- 8 (string-length str)) #\=))))
               (check-exception (base32-decode str no-padding: #t) ContractViolation?)
               (check-exception (base32-decode padded) ContractViolation?)
               (check-exception (base32-decode-lenient str) ContractViolation?)
               (check-exception (base32-decode-lenient padded) ContractViolation?))
             (loop (+ value 1)))))
       '("A" "AAA" "AAAA" "AAAAAA") '(2 4 1 3)))
    (test-case "pad-bit diagnostics identify the public decoder and original position"
      (def (diagnostic decode input)
        (with-catch (lambda (e) (if (ContractViolation? e) (error-irritants e) (raise e)))
          (lambda () (decode input))))
      (check-function diagnostic
        base32-decode "MZ======"
        => '(base32-decode contract: "Nonzero Base32 unused pad bits" index: 1 length: 8 char: #\Z)
        base32-decode-lenient " M-Z "
        => '(base32-decode-lenient contract: "Nonzero Base32 unused pad bits" index: 3 length: 5 char: #\Z)))

    (test-case "canonical Base32 inputs accepted by liboath 2.6.11"
      (check-function base32-decode-lenient
        "MY = = = = = = " => #u8(102)
        "MZXW6= ==" => #u8(102 111 111)
        "   " => #u8()))

    (test-case "lenient decoding of human-entered secrets"
      ;; Key Uri Format example: JBSWY3DPEHPK3PXP = "Hello!" DE AD BE EF.
      (def hello-bytes #u8(72 101 108 108 111 33 #xDE #xAD #xBE #xEF))
      ;; oathtool --base32 example: ASCII "12345678901234567890".
      (def oath-bytes (string->bytes "12345678901234567890"))
      (check-function base32-decode-lenient
        "mZxW6yTb" => #u8(102 111 111 98 97)
        ;; Key Uri Format example, plain and dash-grouped.
        "JBSWY3DPEHPK3PXP" => hello-bytes
        "jbswy3dpehpk3pxp" => hello-bytes
        "JBSW-Y3DP-EHPK-3PXP" => hello-bytes
        "jbsw y3dp ehpk 3pxp" => hello-bytes
        "JBSWY3DPEHPK3PXP======" =>! ContractViolation?
        "-JBSW--Y3DP-EHPK-3PXP-" => hello-bytes
        ;; The same OTP secret with different grouping and separators.
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" => oath-bytes
        "gezd gnbv gy3t qojq gezd gnbv gy3t qojq" => oath-bytes
        "GEZD\tGNBV\nGY3T\r\nQOJQ GEZD-GNBV  GY3T\t\tQOJQ\n" => oath-bytes
        "  gezdgnbvgy3tqojqgezdgnbvgy3tqojq  " => oath-bytes
        ;; Ignored characters may appear anywhere, including around and between padding.
        "MZXQ" => #u8(102 111)
        "M Z X Q" => #u8(102 111)
        "M-Z-X-Q" => #u8(102 111)
        "MZ\nXQ" => #u8(102 111)
        "\tMZXQ\r\n" => #u8(102 111)
        "MZXQ====" => #u8(102 111)
        "MZXQ =" =>! ContractViolation?
        "MZXQ= = =\n" =>! ContractViolation?
        "MZXQ-==-" =>! ContractViolation?
        "mzxq ====" => #u8(102 111)
        ;; Empty data, with or without ignored characters and padding.
        "" => #u8()
        " " => #u8()
        "-" => #u8()
        "=" =>! ContractViolation?
        "========" =>! ContractViolation?
        " \t\r\n- =" =>! ContractViolation?
        "--==--" =>! ContractViolation?)
      ;; Malformed inputs, including nonzero unused bits.
      (check-function base32-decode-lenient
        "MZ" =>! ContractViolation?
        "A" =>! ContractViolation?
        "AAA" =>! ContractViolation?
        "AAAAAA" =>! ContractViolation?
        "AAAAAAAAA" =>! ContractViolation?
        "AAAAAAAAAAA" =>! ContractViolation?
        "AAAAAAAAAAAAAA" =>! ContractViolation?
        "A=" =>! ContractViolation?
        "A=======" =>! ContractViolation?
        "AAA=====" =>! ContractViolation?
        "AAAAAA==" =>! ContractViolation?
        "A B C" =>! ContractViolation?
        "M-Y-Z" =>! ContractViolation?
        "jbsw y3dp ehpk 3p" =>! ContractViolation?
        "=A" =>! ContractViolation?
        "M=Y" =>! ContractViolation?
        "MY=A" =>! ContractViolation?
        "MY=======MY" =>! ContractViolation?
        "MY== A" =>! ContractViolation?
        "MY=-Y" =>! ContractViolation?
        "=Y======" =>! ContractViolation?
        "M0" =>! ContractViolation?
        "M1" =>! ContractViolation?
        "M8" =>! ContractViolation?
        "M9" =>! ContractViolation?
        "M+" =>! ContractViolation?
        "M/" =>! ContractViolation?
        "M_" =>! ContractViolation?
        "M." =>! ContractViolation?
        "M," =>! ContractViolation?
        "M:" =>! ContractViolation?
        "M\x00;" =>! ContractViolation?
        "M\x7f;" =>! ContractViolation?
        "M\xa0;" =>! ContractViolation?
        "M\x100;" =>! ContractViolation?
        "M\x3000;" =>! ContractViolation?
        "M\x0b;Y" =>! ContractViolation?
        "M\x0c;Y" =>! ContractViolation?))))
