;;; -*- Gerbil -*-
;;; © Gerbil contributors
(import :std/test
        :std/error
        ./device
        ./pty)
(export pty-test)

(def pty-test
  (test-suite "POSIX terminals"
    (test-case "terminal size round trip and device ownership"
      (let-values (((master slave) (open-pty rows: 25 columns: 90)))
        (unwind-protect!
          (begin
            (let-values (((rows columns) (terminal-size (OSDevice-fd master))))
              (check rows => 25)
              (check columns => 90))
            (terminal-resize! (OSDevice-fd master) 50 120)
            (let-values (((rows columns) (terminal-size (OSDevice-fd slave))))
              (check rows => 50)
              (check columns => 120)))
          (device-close master)
          (device-close slave))))

    (test-case "raw mode restores terminal translation after exceptions"
      (let-values (((master slave) (open-pty)))
        (unwind-protect!
          (let ((input #u8(13)) (output (make-u8vector 1)))
            (check-exception
             (call-with-terminal-raw-mode (OSDevice-fd slave)
               (lambda ()
                 (check (device-write master input 0 1) => 1)
                 (check (device-read slave output 0 1) => 1)
                 (check output => #u8(13))
                 (error "leave raw mode")))
             Error?)
            (check (device-write master input 0 1) => 1)
            (check (device-read slave output 0 1) => 1)
            (check output => #u8(10)))
          (device-close master)
          (device-close slave))))

    (test-case "terminal dimensions are bounded by the native field size"
      (check-exception (open-pty rows: -1) ContractViolation?)
      (check-exception (open-pty columns: 65536) ContractViolation?))))
