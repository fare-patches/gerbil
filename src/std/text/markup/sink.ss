;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; The stdio output buffers the XML and HTML writers serialize into: one in
;;; memory, or one over the sink they write to. Unchecked internals of
;;; :std/text/markup.
(import :std/error
        :std/io
        :std/io/bio/types
        (only-in :std/io/bio/buffer buffer-detach!)
        (only-in :std/io/bio/cache buffer-cache.get)
        (only-in ./output make-memory-output))
(export memory-output-u8vector
        write-to-sink)
(declare (not safe))

;;; The bytes written into out, as a u8vector: out's buffer, taken.
(def (memory-output-u8vector (out :- memory-output-buffer)) => :u8vector
  (get-memory-output-u8vector (BufferedWriter out)))

;;; Writes what (emit! out) emits into a stdio output buffer out to sink:
;;; - a BufferedWriter with a stdio output buffer: into that buffer, which
;;;   is left unflushed, as the caller's;
;;; - another Writer: through a temporary buffer over it (see
;;;   through-temporary-buffer!), leaving the Writer open;
;;; - an output port: into memory, then to the port through its stdio
;;;   writer, so that the port receives nothing when emit! raises. A byte
;;;   port's writer has no buffer and writes through to the port; a
;;;   character port's decodes the UTF-8 through a temporary buffer,
;;;   leaving the port open.
;;; False, without calling emit!, for any other sink.
(def (write-to-sink (sink  :- :t)
                    (emit! :- :procedure)) => :boolean
  (cond
   ((is-BufferedWriter? sink)
    (let (bio (&interface-instance-object (BufferedWriter sink)))
      (if (basic-output-buffer? bio)
        (using (bio :- basic-output-buffer)
          (when bio.closed?
            (raise-io-closed write-to-sink "buffer closed"))
          (emit! bio))
        (through-sink-buffer! (Writer sink) emit!))
      #t))
   ((is-Writer? sink)
    (through-sink-buffer! (Writer sink) emit!)
    #t)
   ((output-port? sink)
    (using (out (make-memory-output) :- memory-output-buffer)
      (emit! out)
      (using (writer (open-output-port-buffered-writer sink) :- BufferedWriter)
        (if (binary-port? sink)
          (writer.write out.buf 0 out.whi)
          (through-temporary-buffer! writer
                                     (lambda (_) (writer.write out.buf 0 out.whi))))))
    #t)
   (else #f)))

(def (through-sink-buffer! (writer :- Writer)
                           (emit!  :- :procedure)) => :void
  (through-temporary-buffer! (open-sink-buffered-writer writer
                                                        (buffer-cache.get default-buffer-size)
                                                        #t)
                             emit!))

;;; Calls (emit! out) with the stdio output buffer out of buffered, a
;;; BufferedWriter over the caller's sink whose buffer came from the
;;; buffer cache, and flushes it; then releases the buffer to the
;;; cache, leaving the sink open. When emit! or a write to the sink raises,
;;; the bytes not yet written are discarded, not written, before the
;;; release, and the exception propagates as raised.
(def (through-temporary-buffer! (buffered :- BufferedWriter)
                                (emit!    :- :procedure)) => :void
  (using (out (&interface-instance-object buffered) :- basic-output-buffer)
    (unwind-protect
      (begin
        (emit! out)
        (buffered.flush))
      (set! out.whi 0)
      (buffer-detach! buffered))))
