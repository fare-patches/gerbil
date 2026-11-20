;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; bio-output-reserve! tests
(import :std/test
        :std/error
        :std/interface
        ../interface
        ./types
        ./cache
        ./output
        ./api)
(export output-test)

;; Writes bytes at whi, as a caller of bio-output-reserve! does.
(def (put-bytes! (bio : basic-output-buffer) (bytes : :u8vector))
  => :void
  (let (buf (bio-output-reserve! bio (u8vector-length bytes)))
    (subu8vector-move! bytes 0 (u8vector-length bytes) buf bio.whi))
  (set! bio.whi (fx+ bio.whi (u8vector-length bytes))))

(def (memory-output-bytes (mem : memory-output-buffer))
  => :u8vector
  (get-memory-output-u8vector (BufferedWriter mem)))

;; A Writer that fails every write.
(defstruct failing-writer ())

(defmethod {write failing-writer}
  (lambda (self input start end)
    (raise-io-error failing-writer "sink failure"))
  interface: Writer)

(defmethod {close failing-writer}
  void
  interface: Closer)

(@implement Writer failing-writer)

(def output-test
  (test-suite "bio-output-reserve!"
    (test-case "memory buffer: room already there"
      (using (mem (make-memory-output-buffer (make-u8vector 8) #f #f 2) :- memory-output-buffer)
        (let (buf mem.buf)
          (check (eq? (bio-output-reserve! mem 6) buf) => #t)
          (check (eq? mem.buf buf) => #t)
          (check mem.whi => 2))))

    (test-case "memory buffer: the returned vector is the grown buffer"
      (using (mem (make-memory-output-buffer (make-u8vector 4) #f #f 3) :- memory-output-buffer)
        (let (buf (bio-output-reserve! mem 10))
          (check (eq? buf mem.buf) => #t)
          (check (>= (u8vector-length buf) 13) => #t))))

    (test-case "memory buffer: a request past any buffer size raises"
      (using (mem (make-memory-output-buffer (make-u8vector 8) #f #f 4) :- memory-output-buffer)
        (let (buf mem.buf)
          (check-exception (bio-output-reserve! mem (- (expt 2 60) 2)) contract-violation-error?)
          (check (eq? mem.buf buf) => #t)
          (check mem.whi => 4))))

    (test-case "cached buffer: growth gives the old buffer back to the cache"
      (let (old (buffer-cache.get 8))
        (using (mem (make-memory-output-buffer old #f #t 0) :- memory-output-buffer)
          (put-bytes! mem #u8(1 2 3 4 5 6))
          (bio-output-reserve! mem 16)
          (check (eq? mem.buf old) => #f)
          (check mem.cached? => #f)
          (check (subu8vector mem.buf 0 6) => #u8(1 2 3 4 5 6))
          (check (eq? (buffer-cache.get 8) old) => #t))))

    (test-case "memory buffer: reserve larger than capacity keeps the bytes"
      (using (mem (make-memory-output-buffer (make-u8vector 4) #f #f 0) :- memory-output-buffer)
        (put-bytes! mem #u8(1 2 3))
        (bio-output-reserve! mem 100)
        (check mem.whi => 3)
        (check (>= (u8vector-length mem.buf) 103) => #t)
        (check (subu8vector mem.buf 0 3) => #u8(1 2 3))
        (put-bytes! mem #u8(4 5))
        (check (memory-output-bytes mem) => #u8(1 2 3 4 5))))

    (test-case "memory buffer: repeated growth keeps the bytes"
      (let ((mem (make-memory-output-buffer (make-u8vector 1) #f #f 0))
            (expected (make-u8vector 1000)))
        (let loop ((i 0))
          (when (fx< i 1000)
            (u8vector-set! expected i (fxmodulo i 256))
            (put-bytes! mem (u8vector (fxmodulo i 256)))
            (loop (fx+ i 1))))
        (check (memory-output-bytes mem) => expected)))

    (test-case "memory buffer: rolling whi back discards what follows"
      (using (mem (make-memory-output-buffer (make-u8vector 4) #f #f 0) :- memory-output-buffer)
        (put-bytes! mem #u8(1 2))
        (let (mark mem.whi)
          (put-bytes! mem #u8(3 4 5 6 7 8))
          (set! mem.whi mark))
        (put-bytes! mem #u8(9))
        (check (memory-output-bytes mem) => #u8(1 2 9))))

    (test-case "sink buffer: drains to its writer, then reserves"
      (using ((target (open-buffered-writer #f) : BufferedWriter)
              (snk (make-sink-output-buffer (make-u8vector 8) #f #f 0 (Writer target))
                   :- sink-output-buffer))
        (put-bytes! snk #u8(1 2 3 4 5 6))
        (let (buf snk.buf)
          (bio-output-reserve! snk 4)
          (check snk.whi => 0)
          (check (eq? snk.buf buf) => #t))
        (put-bytes! snk #u8(7 8 9 10))
        (BufferedWriter-flush (BufferedWriter snk))
        (check (get-memory-output-u8vector target) => #u8(1 2 3 4 5 6 7 8 9 10))))

    (test-case "sink buffer: drains, then grows for a reserve larger than capacity"
      (using ((target (open-buffered-writer #f) : BufferedWriter)
              (snk (make-sink-output-buffer (make-u8vector 8) #f #f 0 (Writer target))
                   :- sink-output-buffer))
        (put-bytes! snk #u8(1 2 3))
        (bio-output-reserve! snk 20)
        (check snk.whi => 0)
        (check (>= (u8vector-length snk.buf) 20) => #t)
        (put-bytes! snk (make-u8vector 20 7))
        (BufferedWriter-flush (BufferedWriter snk))
        (check (get-memory-output-u8vector target)
               => (u8vector-append #u8(1 2 3) (make-u8vector 20 7)))))

    (test-case "sink buffer: a failing writer raises and keeps the bytes"
      (using (snk (make-sink-output-buffer (make-u8vector 4) #f #f 0
                                           (Writer (make-failing-writer)))
                  :- sink-output-buffer)
        (put-bytes! snk #u8(1 2 3))
        (check-exception (bio-output-reserve! snk 2) io-error?)
        (check snk.whi => 3)
        (check (subu8vector snk.buf 0 3) => #u8(1 2 3))))

    (test-case "string port buffer: keeps a split UTF-8 sequence across the drain"
      ;; "ab" and the first byte of U+4E2D fill all but one byte; the drain
      ;; writes "ab" and keeps the incomplete sequence for the rest.
      (using ((port (open-output-string) : :port)
              (spob (make-string-port-output-buffer (make-u8vector 4) #f #f 0 port)
                    :- string-port-output-buffer)
              (bytes (string->utf8 "ab\u4e2dc") : :u8vector))
        (put-bytes! spob (subu8vector bytes 0 3))
        (bio-output-reserve! spob 3)
        (check (get-output-string port) => "ab")
        (check spob.whi => 1)
        (put-bytes! spob (subu8vector bytes 3 6))
        (BufferedWriter-flush (BufferedWriter spob))
        ;; get-output-string took "ab" from the port
        (check (get-output-string port) => "\u4e2dc")))

    (test-case "closed buffer"
      (let (mem (make-memory-output-buffer (make-u8vector 4) #f #f 0))
        (BufferedWriter-close (BufferedWriter mem))
        (check-exception (bio-output-reserve! mem 1) io-closed-error?)))))
