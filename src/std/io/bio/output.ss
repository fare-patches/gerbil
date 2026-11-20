;;; -*- Gerbil -*-
;;; © vyzo
;;; buffered output
(import :std/error
        ../interface/base
        ../interface/bio
        ./types
        ./buffer
        ./cache
        ./macros)
(export #t)
(declare (not safe))

(defrule (__bio-output-advance! output whi)
  (using (bio output :- basic-output-buffer)
    (set! bio.whi whi)))

(defrule (__bio-output-consume! output)
  (using (bio output :- basic-output-buffer)
    (set! bio.whi 0)))

(defrules __bio-write ()
  ((_ output-buffer input input-start input-end
      __drain!
      __write
      __retry)
   (using (bio output-buffer :- basic-output-buffer)
     (let* ((output-want (fx- input-end input-start))
            (whi bio.whi)
            (whi+want (fx+ whi output-want))
            (buf bio.buf)
            (buflen (u8vector-length buf)))
       (cond
        ((fx<= whi+want buflen)
         ;; have space in buffer
         (subu8vector-move! input input-start input-end buf whi)
         (__bio-output-advance! bio whi+want)
         output-want)
        ;; not enough space
        ((fx> whi 0)
         ;; have some in the buffer, drain it and recurse
         (__drain! bio buf whi)
         (__retry bio input input-start input-end))
        ;; empty buffer
        ((fx>= output-want buflen)
         ;; large write, do it unbuffered
         (__write bio input input-start input-end))
        (else
         ;; fits in buffer, copy it
         (subu8vector-move! input input-start input-end buf 0)
         (__bio-output-advance! bio output-want)
         output-want)))))
  ((_ output-buffer input input-start input-end)
   (__bio-write output-buffer input input-start input-end
                __bio-output-buffer-drain!
                __bio-output-buffer-write
                __bio-output-buffer-write)))

(defrules __bio-write-u8 ()
  ((_ output-buffer u8 __drain! __retry)
   (using (bio output-buffer :- basic-output-buffer)
     (let* ((whi bio.whi)
            (buf bio.buf)
            (buflen (u8vector-length buf)))
       (if (fx< whi buflen)
         (let (whi+1 (fx+ whi 1))
           (u8vector-set! buf whi u8)
           (__bio-output-advance! bio whi+1)
           1)
         ;; full buffer
         (begin
           (__drain! bio buf whi)
           (__retry bio u8))))))
  ((_ output-buffer u8)
   (__bio-write-u8 __bio-output-buffer-drain! __bio-output-buffer-write-u8)))

(defrules __bio-flush-output ()
  ((_ output-buffer __drain!)
   (using (bio output-buffer :- basic-output-buffer)
     (let* ((whi bio.whi)
            (buf bio.buf))
       (when (fx> whi 0)
         (__drain! bio buf whi)
         (void)))))
  ((_ output-buffer)
   (__bio-flush-output output-buffer __bio-output-buffer-drain!)))

(defrules __bio-close-output ()
  ((_ output-buffer __close __drain!)
   (using (bio output-buffer :- basic-output-buffer)
     (let (exn #f)
       (unless bio.closed?
         (set! bio.closed? #t)
         (with-catch (lambda (e) (set! exn e)) (cut __drain! bio bio.buf bio.whi))
         (when bio.cached?
           (buffer-cache.put! bio.buf))
         (set! bio.buf #f)
         (__close bio)
         (when exn (raise exn))))))
  ((_ output-buffer)
   (__bio-close-output __bio-output-buffer-close __bio-output-buffer-drain!)))

;; Ensures room for n bytes at whi and returns the u8vector that holds
;; [whi, whi + n), the buffer's buf; the caller writes the bytes there and
;; advances whi. When the room is short, a buffer other than a memory buffer
;; is drained first, which moves whi to 0 (a string port buffer keeps a
;; partial UTF-8 sequence at [0, whi)), and the buffer then grows if it
;; still lacks the room, keeping [0, whi); a memory buffer only grows, so it
;; keeps all of its output. The vector and the range are valid until the
;; next operation on the buffer (write, write-u8, flush, drain! or another
;; reserve), which may replace buf or move its bytes. A request for a
;; buffer past the fixnum range raises ContractViolation.
;; A grown buffer is a new one, not one from the buffer cache: growing
;; memory buffers through the cache took 7 times the page faults, 5 times
;; the kernel cycles and 20% to 30% more cycles in all writing a large
;; HTML document into memory (:std/text/markup's markup-benchmark.ss mode
;; html-write-elements, SIZE 1000, ITERATIONS 300).
(def (bio-output-reserve! (bio : basic-output-buffer)
                          (n   :~ nonnegative-fixnum? :- :fixnum))
  => :u8vector
  (__check-buffer-open! bio-output-reserve! bio)
  (when (fx> n (fx- (u8vector-length bio.buf) bio.whi))
    (when (and (fx> bio.whi 0) (not (memory-output-buffer? bio)))
      (__bio-output-buffer-drain! bio bio.buf bio.whi))
    (let ((buf bio.buf)
          (whi bio.whi))
      (when (fx> n (fx- (u8vector-length buf) whi))
        ;; generic arithmetic, so that the size cannot wrap
        (let (size (max (+ whi n) (* 2 (u8vector-length buf))))
          (unless (fixnum? size)
            (raise-bad-argument bio-output-reserve! "buffer size" n))
          (let (new-buf (make-u8vector size))
            (subu8vector-move! buf 0 whi new-buf 0)
            (when bio.cached?
              (buffer-cache.put! buf))
            (set! bio.buf new-buf)
            (set! bio.cached? #f))))))
  bio.buf)
