;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; XML writer: serializes typed XML nodes as UTF-8.
(import :std/error
        :std/io/bio/types
        (only-in ../output make-memory-output memory-output-string)
        ../sink
        ./node
        ./emitter)
(export write-xml
        xml->u8vector
        xml->string)

;;; What the writers take: a document or any node.
(def (xml-writable? (x : :t)) => :boolean
  (or (XMLDocument? x) (xml-node? x)))

;;; Writes node, a document or any node, as UTF-8 to sink: a Writer (including
;;; a BufferedWriter), a byte port, or a character port (as characters).
;;; Raises ContractViolation for what XML cannot represent; xml.md gives the
;;; output and every rejected case.
(def (write-xml (node :~ xml-writable? :- XML)
                (sink :  :t := (current-output-port))) => :void
  (unless (write-to-sink sink (lambda ((out :- basic-output-buffer))
                                (emit-xml! (make-xml-emitter out) node)))
    (raise-bad-argument write-xml "Writer or output port" sink)))

;;; node written into memory.
(def (memory-output (node :- XML)) => memory-output-buffer
  (let (out (make-memory-output))
    (emit-xml! (make-xml-emitter out) node)
    out))

(def (xml->u8vector (node :~ xml-writable? :- XML)) => :u8vector
  (memory-output-u8vector (memory-output node)))

(def (xml->string (node :~ xml-writable? :- XML)) => :string
  (memory-output-string (memory-output node)))
