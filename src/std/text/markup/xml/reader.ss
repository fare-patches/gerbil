;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; XML reader: parses a whole document into a typed tree.
(import :std/error
        (only-in ../input source->scan-input)
        ./node
        ./scanner)
(export read-xml
        XMLParseError
        XMLParseError?
        xml-parse-error?
        XMLParseError-offset)

;;; Parses one XML document from source: a u8vector, a string, an input
;;; port or a Reader, read to end of input. Raises XMLParseError (an
;;; IOError) at the first well-formedness or namespace error. xml.md gives
;;; the encodings, options and error offsets.
(def (read-xml (source                         : :t)
               keep-space?:    (keep-space?    : :boolean := #f)
               keep-comments?: (keep-comments? : :boolean := #f)) => XMLDocument
  (defvalues (buf mapped?) (source->scan-input source string->xml-scan-input))
  (unless buf
    (raise-bad-argument read-xml "u8vector, string, input port or Reader" source))
  (scan-xml-document buf (fx- (u8vector-length buf) 1) mapped? keep-space? keep-comments?))
