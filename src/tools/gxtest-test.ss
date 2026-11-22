;;; -*- Gerbil -*-
;;; gxtest exit-status regression tests.
;;; A failing test run must exit nonzero through every entry point:
;;; `gerbil test`, `gxtest`, and the top-level `./build.sh test`.
;;; Fixtures are written to a temporary directory at setup time and are named
;;; without the -test.ss suffix, so test discovery never picks them up.
(import :std/test
        :std/source
        :std/io/tempfile
        :std/misc/process)
(export gxtest-test test-setup! test-cleanup!)

(def test-directory (make-temporary-file-name "gerbil-gxtest-test-"))
(def top-build.sh (path-expand "../../build.sh" (this-source-directory)))

(def (fixture-path (name : :string))
  => :string
  (path-expand (string-append name "-fixture.ss") test-directory))

(def (write-fixture (name : :string) (body : :string))
  => :void
  (write-file-string (fixture-path name)
    (string-append "(import :std/test)\n"
                   "(export " name "-fixture-test)\n"
                   "(def " name "-fixture-test\n"
                   "  (test-suite \"" name " fixture\"\n"
                   body "))\n")))

(def (test-setup!)
  => :void
  (create-directory test-directory)
  (write-fixture "passing"
    "    (test-case \"passes\" (check-equal? 1 1))")
  (write-fixture "failing"
    (string-append
     "    (test-case \"passes\" (check-equal? 1 1))\n"
     "    (test-case \"fails deliberately\" (check-equal? 1 2))")))

(def (test-cleanup!)
  => :void
  (clear-temporary-file! test-directory))

;; Run `command ... <fixture>` in a subprocess; return its exit code.
;; Output is captured and discarded: the failing fixture is noisy by design.
(def (tool-exit-code (command : :list) (fixture : :string))
  => :fixnum
  (let (status #f)
    (run-process (append command [(fixture-path fixture)])
                 directory: test-directory
                 stderr-redirection: #t
                 check-status: (lambda (st _settings) (set! status st)))
    ;; Gambit's process-status is a waitpid status word: exit code in bits 8-15.
    ;; TODO: decode signal terminations distinctly if they ever matter here.
    (fxand (fxarithmetic-shift-right status 8) 255)))

(def gerbil-test ["gerbil" "test"])
(def gxtest ["gxtest"])
(def build.sh-test [top-build.sh "test"])

(def gxtest-test
  (test-suite "gxtest exit status"
    ;; One test-case per failing entry point: a failed check aborts its
    ;; test-case, and we want each broken entry point reported separately.
    (test-case "all entry points exit 0 on success"
      (check-function tool-exit-code
        gerbil-test "passing" => 0
        gxtest "passing" => 0
        build.sh-test "passing" => 0))

    (test-case "gerbil test exits 42 on failure"
      (check (tool-exit-code gerbil-test "failing") => 42))

    (test-case "gxtest exits 42 on failure"
      (check (tool-exit-code gxtest "failing") => 42))

    ;; build.sh maps any nonzero status to its own `die` exit code.
    (test-case "./build.sh test exits nonzero on failure"
      (check (tool-exit-code build.sh-test "failing") ? positive?))))
