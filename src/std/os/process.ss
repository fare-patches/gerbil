;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Owned native processes with separate IO and optional controlling terminals
(import :std/error
        :std/interface
        :std/io/interface
        :std/io/file
        :std/sync/threads
        :std/vector/u8vector
        ./device
        ./file
        ./error
        ./signal
        ./pty
        ./process-native)
(export (interface-out Process)
        (struct-out ProcessExit)
        start-process!)

(defrule (process-grace? value)
  (and (real? value) (<= 0 value 2147483)))

(defstruct ProcessExit
  ((code   :? :fixnum := #f)
   (signal :? :fixnum := #f))
  final: #t)

(interface (Process Closer)
  (pid)
  => :fixnum
  (stdin)
  => (Maybe Writer)
  (stdout)
  => Reader
  (stderr)
  => (Maybe Reader)
  (terminal?)
  => :boolean
  (wait timeout: (timeout : :t := #f))
  => ProcessExit
  (signal (signo :~ (in-range? 1 SIGMAX) :- :fixnum)
          group: (group? : :boolean := #t))
  => :void
  (stop)
  => :void
  (resize (rows :~ (in-range-inclusive? 0 65535) :- :fixnum)
          (columns :~ (in-range-inclusive? 0 65535) :- :fixnum))
  => :void)

(defclass native-process
  ((pid        :  :fixnum := 0)
   (terminal?  :  :boolean := #f)
   (control    :? Writer := #f)
   (events     :? Reader := #f)
   (input      :? Writer := #f)
   (output     :? Reader := #f)
   (errors     :? Reader := #f)
   (master     :? FileDevice := #f)
   (child      :? :foreign := #f)
   (grace      :  :real := 5)
   (stopper    :? :thread := #f)
   (observer   :? :thread := #f)
   (closed?    :  :boolean := #f)
   (mutex      :- :mutex := (make-mutex 'native-process))
   (command    :- :u8vector := (make-u8vector 8)))
  final: #t)

;; Linux PTY masters report EIO when the final slave closes. Preserve Reader's
;; minimum-read contract while presenting that terminal hangup as ordinary EOF.
(defclass terminal-reader
  ((input : Reader))
  final: #t)
(implement Closer terminal-reader
  (close
   (lambda (self)
     (self.input.close))))
(implement Reader terminal-reader
  (read
   (lambda (self output start end need)
     (: (try
         (self.input.read output start end need)
         (catch (e)
           (if (and (os-error? e) (fx= (OSError-errno e) EIO))
             (if (fxpositive? need)
               (raise-premature-end-of-input terminal-reader need)
               0)
             (raise e))))
        :fixnum))))

;; Only the payload receives this environment; the monitor starts with an empty
;; environment. These bytes become C strings only at the payload exec boundary.
(def (process-send-environment! (control     : Writer)
                                (environment : :list)
                                (buffer      : :u8vector))
  => :void
  (u8vector-u32-native-set! buffer 0 (length environment))
  (control.write buffer 0 4)
  (for-each
   (lambda ((entry :- :string))
     (when (string-index entry (integer->char 0))
       (raise-contract-violation start-process! "NUL in process environment"))
     (let (bytes (string->utf8 entry))
       (u8vector-u32-native-set! buffer 0 (u8vector-length bytes))
       (control.write buffer 0 4)
       (control.write bytes)))
   environment))

(def (process-event (reader : Reader)
                     (buffer : :u8vector))
  => :values
  (reader.read buffer 0 8 8)
  (values (u8vector-s32-native-ref buffer 0)
          (u8vector-s32-native-ref buffer 4)))

(def (process-exit (value : :fixnum))
  => ProcessExit
  (if (fxnegative? value)
    (make-ProcessExit signal: (fx- value))
    (make-ProcessExit code: value)))

(def (check-process-exec! (events : Reader) (buffer : :u8vector) (path : :string))
  => :void
  (unwind-protect!
    (let (n (events.read buffer 0 4 0))
      ;; Successful exec closes the writer. A setup failure writes a native int32 errno.
      (unless (fxzero? n)
        (when (fx< n 4) (events.read buffer n 4 (fx- 4 n)))
        (let (errno (u8vector-s32-native-ref buffer 0))
          (raise-os-error start-process! errno path: path))))
    (events.close)))

;; A Process can outlive both the thread group that starts it and the one that stops it.
(def process-thread-group (make-detached-thread-group 'native-process))

(def (direct-process-exit-thread (dev : :foreign))
  => ProcessExit
  (let (event (##make-io-condvar-for-event dev))
    (let loop ()
      (let (status (##os-device-process-status dev))
        (if status
          (process-exit (native-process-exit-value status))
          (begin (##wait-for-io! event #t) (loop)))))))

(def (monitor-process-exit-thread (events : Reader)
                          (buffer : :u8vector))
  => ProcessExit
  (unwind-protect!
    (let-values (((kind value) (process-event events buffer)))
      (case kind
        ((2) (process-exit value))
        ((3) (raise-os-error Process.wait value))
        (else (raise-io-error Process.wait "invalid native monitor event" kind))))
    (events.close)))

;; Start an executable with argv including argv[0], like std/os/exec.
;; Use gxexec for managed jobs: its monitor survives owner death, sends TERM/CONT
;; to the payload group, escalates to KILL after grace, and cleans up remaining
;; group members on leader exit. Jobs that leave the group can survive.
;; The default launches the payload directly and manages only its PID. Requesting
;; gxexec: #t requires a working helper; failure to launch it raises OSError.
;; On Linux, cgroup: selects a delegated cgroup v2 root. gxexec creates a
;; leaf per launch and waits for it to empty before reporting the payload exit.
(def (start-process! (path : :string)
                     (argv :~ (list-of? string?) :- :list)
                     environment: (environment :~ (list-of? string?) :- :list :=
                                  (map (lambda (entry) (string-append (car entry) "=" (cdr entry)))
                                       (get-environment-variables)))
                     directory: (directory : :string := (current-directory))
                     terminal: (terminal? : :boolean := #f)
                     stdin-redirection: (pipe-in? : :boolean := #t)
                     stderr-to-stdout: (merged? : :boolean := #f)
                     rows: (rows :~ (in-range-inclusive? 0 65535) :- :fixnum := 24)
                     columns: (columns :~ (in-range-inclusive? 0 65535) :- :fixnum := 80)
                     grace: (grace :~ process-grace? :- :real := 5)
                     gxexec: (gxexec? : :boolean := #f)
                     cgroup: (cgroup :? :string := #f)
                     helper: (helper : :string := "~~bin/gxexec"))
  => Process
  (when (null? argv)
    (raise-bad-argument start-process! "nonempty argv including argv[0]" argv))
  (when cgroup
    (cond-expand
      (linux
       (unless gxexec?
         (raise-bad-argument start-process! "cgroup execution requires gxexec" cgroup)))
      (else
       (raise-context-error start-process! "cgroup execution unsupported on this platform"
                            (system-type-string)))))
  (let ((fds (make-process_fds))
        (buffer (make-u8vector 8))
        (owned? #f))
    (using (self (native-process terminal?: terminal? grace: grace) : native-process)
      (do-syscall (native-process-prepare! fds (if gxexec? 1 0) (if terminal? 1 0)
                                           (if merged? 1 0) (if pipe-in? 1 0) rows columns))
      (unwind-protect!
        (begin
          (set! self.events (Reader (InputFileIO dev: (native-process-take-device! fds 1 DIRECTION-IN))))
          (when gxexec?
            (set! self.control (Writer (OutputFileIO dev: (native-process-take-device! fds 0 DIRECTION-OUT)))))
          (alet (input (native-process-take-device! fds 2 DIRECTION-OUT))
            (set! self.input (Writer (OutputFileIO dev: input))))
          (let (output (native-process-take-device! fds 3 DIRECTION-IN))
            (when terminal? (set! self.master output))
            (set! self.output (Reader (InputFileIO dev: output)))
            (when terminal?
              (set! self.output (Reader (terminal-reader input: self.output)))))
          (alet (errors (native-process-take-device! fds 4 DIRECTION-IN))
            (set! self.errors (Reader (InputFileIO dev: errors))))
          (let* ((cwd (path-expand directory))
                 (executable (path-expand path cwd)))
            (if gxexec?
              (let (monitor (path-expand helper))
                (native-spawn-monitor! fds monitor
                  (append [monitor (if cgroup "2" "1") (if terminal? "pty" "pipe")
                                   (number->string (inexact->exact (floor (* grace 1000))))
                                   cwd]
                          (if cgroup [(path-expand cgroup)] [])
                          [executable]
                          argv)))
              (set! self.child (native-raw-spawn! fds executable argv environment cwd terminal?))))
          (native-process-close-child-fds! fds)
          (if self.child
            (begin
              (check-process-exec! self.events buffer path)
              (set! self.pid (##os-device-process-pid self.child))
              (set! self.observer (spawn-thread (cut direct-process-exit-thread self.child)
                              'process-exit process-thread-group)))
            (begin
              (process-send-environment! self.control environment buffer)
              (let-values (((kind value) (process-event self.events buffer)))
                (case kind
                  ((1) (set! self.pid value))
                  ((3) (raise-os-error start-process! value path: path))
                  (else (raise-io-error start-process! "invalid native monitor startup event" kind))))
              (set! self.observer (spawn-thread (cut monitor-process-exit-thread self.events buffer)
                              'process-exit process-thread-group))))
          (begin0 (Process self) (set! owned? #t)))
        (native-process-discard! fds)
        (unless owned? (native-process-close self))))))

(def (native-process-signal! (self   : native-process)
                             (signo  : :fixnum)
                             (group? : :boolean))
  => :void
  (do-with-lock self.mutex
    (when self.closed?
      (raise-io-closed Process.signal "process closed"))
    (if self.child
      (do-syscall (##os-device-process-signal self.child signo))
      (begin
        (u8vector-s32-native-set! self.command 0 (if group? 2 1))
        (u8vector-s32-native-set! self.command 4 signo)
        (self.control.write self.command))))
  (void))

;; Called with the process mutex held; the timer owns its device until joined.
(def (native-process-stop! (self : native-process))
  => :void
  (cond
   (self.control (self.control.close))
   ((and self.child (not self.stopper))
    (if self.observer
      (begin
        (do-syscall (##os-device-process-signal self.child SIGTERM))
        (do-syscall (##os-device-process-signal self.child SIGCONT))
        (set! self.stopper
          (spawn-thread
           (lambda ()
             (unless (thread-join!/error self.observer self.grace #f)
               (do-syscall (##os-device-process-signal self.child SIGKILL))))
           'process-stop process-thread-group)))
      ;; Construction failed after exec, before an observer could be started.
      (begin
        (do-syscall (##os-device-process-signal self.child SIGKILL))
        (direct-process-exit-thread self.child)))))
  (void))

(def (native-process-close (self : native-process))
  => :void
  (do-with-lock self.mutex
    (unless self.closed?
      (set! self.closed? #t)
      (unwind-protect!
        (native-process-stop! self)
        (when self.input (self.input.close))
        (when self.output (self.output.close))
        (when self.errors (self.errors.close)))))
  (when self.stopper (thread-join!/error self.stopper))
  (if self.observer
    (thread-join!/error self.observer)
    (when self.events (self.events.close)))
  (do-with-lock self.mutex
    (when self.child
      (foreign-release! self.child)
      (set! self.child #f)))
  (void))

(implement Closer native-process
  (close __native-process-close))
(implement Process native-process
  (pid
   (lambda (self)
     self.pid))
  (stdin
   (lambda (self)
     self.input))
  (stdout
   (lambda (self)
     (: self.output Reader)))
  (stderr
   (lambda (self)
     self.errors))
  (terminal?
   (lambda (self)
     self.terminal?))
  (wait
   (lambda (self timeout: timeout)
     (: (thread-join!/error self.observer timeout) ProcessExit)))
  (signal
   (lambda (self signo group: group?)
     (native-process-signal! self signo group?)))
  (stop
   (lambda (self)
     (do-with-lock self.mutex
       (unless self.closed? (native-process-stop! self)))))
  (resize
   (lambda (self rows columns)
     (do-with-lock self.mutex
       (when self.closed? (raise-io-closed Process.resize "process closed"))
       (unless self.master
         (raise-contract-violation Process.resize "process has no terminal"))
       (do-check-device-open Process.resize self.master
         (terminal-resize! self.master.fd rows columns))))))
