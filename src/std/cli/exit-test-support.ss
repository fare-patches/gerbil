;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Test support for process-exit paths: run forms in a child gxi and observe
;;; its exit code and what it left in a file.
;;; Gambit's exit does not unwind, and its exit jobs flush only the console ports:
;;; output written to any other current-output-port is lost unless flushed before exit.
;;; Not in build-spec: tests import it by string path, from source.
(import :std/misc/process
        :std/misc/ports
        :std/io/tempfile)
(export gxi-exit-code gxi-exit-output)

;; Run forms with this installation's gxi. Return its exit code or, for a
;; child killed by a signal, the negative signal number.
(def (gxi-exit-code . forms)
  => :fixnum
  (let (status #f)
    (run-process (cons (path-expand "~~bin/gxi")
                       (foldr (lambda (form args)
                                ["-e" (with-output-to-string (cut write form)) . args])
                              [] forms))
                 stderr-redirection: #t
                 check-status: (lambda (st _settings) (set! status st)))
    (let (signal (fxand status 127))
      (if (fxzero? signal) (fxand (fxarithmetic-shift-right status 8) 255)
        (fx- 0 signal)))))

;; (make-forms file) returns the forms for the child, which may write to the named file.
;; Return (cons exit-code contents), where contents is the file's contents,
;; or #f if the child did not create the file.
(def (gxi-exit-output make-forms)
  ;; Not call-with-temporary-file-name: it is declared to return a :string.
  (let (file (make-temporary-file-name "exit-test"))
    (unwind-protect
      (let (code (apply gxi-exit-code (make-forms file)))
        (cons code (and (file-exists? file) (read-file-string file))))
      (clear-temporary-file! file))))
