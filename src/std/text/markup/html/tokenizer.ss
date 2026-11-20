;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HTML tokenizer: the tokens of the WHATWG HTML tokenization stage, one at a
;;; time. A tokenizer is not thread safe.
;;;
;;; Internal, not part of the public HTML API (:std/text/markup/html/reader):
;;; ./reader uses source->html-tokenizer; the rest is the checked interface to
;;; ./scanner that tokenizer-test.ss tests it through.
;;;
;;; html-tokenizer-next! returns the kind of the next token; the accessors
;;; below read the current token and raise unless it has their kind. A
;;; character token is a run of characters (adjacent runs are not merged);
;;; NUL in the data and CDATA states is a token of its own, as the tree
;;; builder handles it apart. The state, last start tag and CDATA flag are
;;; what the tree builder sets as it goes; tokenizing alone keeps the data
;;; state and records start tags. Markup errors are not reported.
(import :std/error
        (only-in ../scan-input string->scan-input)
        (only-in ../input source->scan-input)
        (only-in ./rules
                 html-tag-name?
                 ascii-upper-in?
                 html-state-data
                 html-state-rcdata
                 html-state-rawtext
                 html-state-script-data
                 html-state-plaintext
                 html-state-cdata)
        (rename-in ./scanner
                   (html-tokenizer-next! scanner-next!)
                   (html-token-text scanner-token-text)))
(export make-html-tokenizer
        source->html-tokenizer
        HTMLTokenizer
        HTMLTokenizer?
        html-tokenizer-next!
        html-tokenizer-state-set!
        html-tokenizer-last-start-tag-set!
        html-tokenizer-cdata-set!
        html-token-text
        html-token-tag-name
        html-token-self-closing?
        html-token-attributes
        html-token-data
        html-token-target
        html-token-doctype-name
        html-token-doctype-public-id
        html-token-doctype-system-id
        html-token-force-quirks?
        html-token-eof
        html-token-characters
        html-token-null-character
        html-token-start-tag
        html-token-end-tag
        html-token-comment
        html-token-doctype
        html-token-pi
        html-state-data
        html-state-rcdata
        html-state-rawtext
        html-state-script-data
        html-state-plaintext
        html-state-cdata
        HTMLParseError
        HTMLParseError?
        html-parse-error?
        HTMLParseError-offset)

;;; A tokenizer over source: a u8vector of UTF-8 (a leading byte order mark
;;; is skipped), a string, an input port, or a Reader. Ports and Readers are
;;; read to end of input from their current position; byte ports are decoded
;;; like a u8vector (one that characters were already read from is rejected,
;;; as read-html describes), character ports like a string; a lone surrogate
;;; in a string reads as U+FFFD. In byte input, tokens raise HTMLParseError at
;;; invalid UTF-8; its offset is the byte offset of the ill-formed sequence.
(def (make-html-tokenizer (source : :t)) => HTMLTokenizer
  (or (source->html-tokenizer source)
      (raise-bad-argument make-html-tokenizer "u8vector, string, input port or Reader" source)))

;;; The tokenizer over source, as make-html-tokenizer makes it, or #f when
;;; source is not a u8vector, string, input port or Reader.
(def (source->html-tokenizer (source : :t)) => (Maybe HTMLTokenizer)
  (defvalues (buf mapped?) (source->scan-input source string->scan-input))
  (and buf
       (let* ((end (fx- (u8vector-length buf) 1))
              (bom? (and (not mapped?)
                         (fx>= end 3)
                         (fx= (u8vector-ref buf 0) #xef)
                         (fx= (u8vector-ref buf 1) #xbb)
                         (fx= (u8vector-ref buf 2) #xbf))))
         (scan-input->html-tokenizer buf (if bom? 3 0) end mapped?))))

(def (html-tokenizer-next! (tz : HTMLTokenizer)) => :fixnum
  (scanner-next! tz))

;;; Starts the next token in state, one of the html-state constants.
(def (html-tokenizer-state-set! (tz    : HTMLTokenizer)
                                (state : :fixnum)) => :void
  (unless (and (fx>= state html-state-data) (fx<= state html-state-cdata))
    (raise-bad-argument html-tokenizer-state-set! "html-state constant" state))
  (set! tz.state state))

;;; Makes name (a lower case tag name) the last start tag, which decides the
;;; end tag that ends RCDATA, RAWTEXT and script data; #f for none.
(def (html-tokenizer-last-start-tag-set! (tz   : HTMLTokenizer)
                                         (name :? :string)) => :void
  (when (and name
             (or (not (html-tag-name? name))
                 (ascii-upper-in? name)))
    (raise-bad-argument html-tokenizer-last-start-tag-set! "lower case HTML tag name or #f" name))
  (set! tz.last-start-tag (if name (html-tokenizer-intern tz name) 0)))

;;; Whether <![CDATA[ opens a CDATA section, as it does in foreign content.
(def (html-tokenizer-cdata-set! (tz     : HTMLTokenizer)
                                (cdata? : :boolean)) => :void
  (set! tz.cdata? cdata?))

(defrule (check-kind tz where kind ...)
  (let (current (using (t tz :- HTMLTokenizer) t.kind))
    (unless (or (fx= current kind) ...)
      (raise-bad-argument where "tokenizer at a token of this kind" current))))

;;; (def-token-field (name tz) => type (kind ...) value): an accessor of the
;;; current token, which raises unless the token has one of the kinds.
(defrules def-token-field (=>)
  ((_ (name tz) => type (kind ...) value)
   (def (name (tz : HTMLTokenizer)) => type
     (check-kind tz name kind ...)
     value)))

;;; The characters of a character token.
(def (html-token-text (tz : HTMLTokenizer)) => :string
  (check-kind tz html-token-text html-token-characters)
  (scanner-token-text tz))

;;; The name of a start or end tag.
(def (html-token-tag-name (tz : HTMLTokenizer)) => :string
  (check-kind tz html-token-tag-name html-token-start-tag html-token-end-tag)
  (html-atom-name tz tz.tag))

(def-token-field (html-token-self-closing? tz) => :boolean
  (html-token-start-tag html-token-end-tag)
  tz.self-closing?)

;;; The attributes of a start tag, as (name . value) pairs in order; the first
;;; of attributes with the same name is kept. End tags have none.
(def (html-token-attributes (tz : HTMLTokenizer)) => :list
  (check-kind tz html-token-attributes html-token-start-tag html-token-end-tag)
  (html-token-attribute-list tz (atom value) (cons (html-atom-name tz atom) value)))

;;; The data of a comment or processing instruction.
(def-token-field (html-token-data tz) => :string
  (html-token-comment html-token-pi)
  tz.data)

(def-token-field (html-token-target tz) => :string
  (html-token-pi)
  tz.target)

;;; The DOCTYPE name and identifiers are #f when missing.
(def-token-field (html-token-doctype-name tz) => (Maybe :string)
  (html-token-doctype)
  tz.doctype-name)

(def-token-field (html-token-doctype-public-id tz) => (Maybe :string)
  (html-token-doctype)
  tz.public-id)

(def-token-field (html-token-doctype-system-id tz) => (Maybe :string)
  (html-token-doctype)
  tz.system-id)

(def-token-field (html-token-force-quirks? tz) => :boolean
  (html-token-doctype)
  tz.force-quirks?)
