;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; The sources the XML and HTML readers take, read into scan input buffers
;;; (./scan-input). Unchecked internals of :std/text/markup.
(import :std/io
        (only-in :std/misc/ports read-all-as-string)
        ./scan-input)
(export source->scan-input)
(declare (not safe))

;;; Chunk size for reading byte ports (through a buffered Reader) and
;;; Readers. Of read-all-as-u8vector (8 KB) and read-all-from-reader at its
;;; default 1 KB and at 8, 16, 32 and 64 KB, 16 KB through a Reader took
;;; within 3% of the fewest instructions and 6% of the fewest cycles
;;; reading a 2.5 KB, a 100 KB and a 1.5 MB file (markup-benchmark.ss mode
;;; xml-read-file, SIZE 50, 2000 and 30000, ITERATIONS 20000, 400 and 15).
;;; On the 1.5 MB file, 1 KB took 13% more instructions and 33% more
;;; cycles, and read-all-as-u8vector 5% and 17% more; on the 2.5 KB one,
;;; 64 KB took 16% and 18% more.
(def input-chunk-size 16384)

;;; The scan input of source, a u8vector, string, input port or Reader, and
;;; whether it was mapped (encoded from characters, so offsets in it map to
;;; character indexes); #f and #f for another source. Ports and Readers are
;;; read to end of input from their current position: byte ports like a
;;; Reader, character ports with read-all-as-string.
;;; Characters are encoded with (encode-string str), string->scan-input or a
;;; reader's stricter one.
(def (source->scan-input (source        :- :t)
                         (encode-string :- :procedure)) => :values
  (defrule (bytes-input bytes-expr)
    (let (bytes bytes-expr)
      (values (u8vector->scan-input bytes 0 (##u8vector-length bytes)) #f)))
  (cond
   ((u8vector? source)
    (bytes-input source))
   ((string? source)
    (values (encode-string source) #t))
   ((input-port? source)
    (if (binary-port? source)
      (bytes-input (read-all-from-reader (open-input-port-buffered-reader source)
                                         input-chunk-size))
      (values (encode-string (read-all-as-string source)) #t)))
   ((is-Reader? source)
    (bytes-input (read-all-from-reader (Reader source) input-chunk-size)))
   (else (values #f #f))))
