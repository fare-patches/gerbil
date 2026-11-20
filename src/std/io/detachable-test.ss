;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; detachable readers and writers test
(import :std/test
        :std/error
        ./interface
        ./detachable
        ./bio/api
        (only-in ./bio/buffer buffer-detach!))
(export detachable-test)

(def detachable-test
  (test-suite "detachable readers and writers"
    (test-case "a detachable writer writes through until detached, leaving its writer open"
      (let* ((target (open-buffered-writer #f))
             (writer (open-detachable-writer target)))
        (check (Writer-write writer (string->utf8 "ab") 0 2) => 2)
        (buffer-detach! writer)
        (check-exception (Writer-write writer (string->utf8 "x") 0 1) io-closed-error?)
        ;; closing it detaches it too, again
        (Writer-close writer)
        (check (BufferedWriter-write-u8 target (char->integer #\c)) => 1)
        (check (get-memory-output-u8vector target) => (string->utf8 "abc"))))

    (test-case "a detachable reader reads through until detached, leaving its reader open"
      (let* ((source (open-buffered-reader (string->utf8 "abc")))
             (reader (open-detachable-reader source))
             (buf (make-u8vector 1)))
        (check (Reader-read reader buf 0 1 1) => 1)
        (check buf => (string->utf8 "a"))
        (Reader-close reader)
        (check-exception (Reader-read reader buf 0 1 1) io-closed-error?)
        (buffer-detach! reader)
        (check (BufferedReader-read-u8 source) => (char->integer #\b))))))
