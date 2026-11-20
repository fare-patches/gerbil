;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; HTML reader: parses HTML documents and fragments into typed trees with
;;; the WHATWG HTML parsing algorithm (HTML Living Standard §13.2 and §13.4),
;;; as browsers do.
(import :std/error
        ../xml/node
        ./node
        ./rules
        (only-in ./scanner html-tokenizer-intern)
        (only-in ./tokenizer
                 source->html-tokenizer
                 HTMLParseError
                 HTMLParseError?
                 html-parse-error?
                 HTMLParseError-offset)
        ./builder)
(export read-html
        read-html-fragment
        HTMLParseError
        HTMLParseError?
        html-parse-error?
        HTMLParseError-offset)

(defrule (source-tokenizer source where)
  (or (source->html-tokenizer source)
      (raise-bad-argument where "u8vector, string, input port or Reader" source)))

;;; Parses an HTML document from source: a u8vector of UTF-8, a string, an
;;; input port or a Reader, read to end of input, as browsers do; malformed
;;; markup is never an error. Raises HTMLParseError (an IOError) for invalid
;;; UTF-8 in byte input and for nesting deeper than 512. html.md gives the
;;; tree, the scripting? flag and the nesting rule.
(def (read-html (source                 : :t)
                scripting?: (scripting? : :boolean := #t)) => HTMLDocument
  (build-html-document (source-tokenizer source read-html) scripting?))

;;; What read-html-fragment takes as its context: a tag name or an element.
(def (html-fragment-context? (x : :t)) => :boolean
  (or (string? x) (XMLElement? x)))

;;; Parses an HTML fragment from source, read as read-html reads it, as the
;;; content of a context element, as innerHTML does; returns its nodes.
;;; context is an HTML tag name (ASCII case-insensitive), always naming an
;;; HTML element ("svg" is an HTML element named svg), or an XMLElement
;;; whose name is in no namespace (HTML), svg-namespace-uri or
;;; mathml-namespace-uri, the only way to give an SVG or MathML context; of
;;; its attributes only encoding matters (on a MathML annotation-xml
;;; element), and its children are ignored. The context decides how the
;;; fragment is parsed: "body" parses flow content, "template" any content,
;;; including table rows and cells. An invalid context raises
;;; ContractViolation before anything is read from source.
(def (read-html-fragment (source                 :  :t)
                         context:    (context    :~ html-fragment-context? :- :t := "body")
                         scripting?: (scripting? :  :boolean := #t)) => :list
  (defvalues (ns local name attributes)
    (if (string? context)
      (begin
        (unless (html-tag-name? context)
          (raise-bad-argument read-html-fragment "HTML tag name or XMLElement" context))
        (let (local (ascii-downcase context))
          (values ns-html local (unchecked-node XMLName local "" "") '())))
      (using (context :- XMLElement)
        (let (ns (namespace-code context.name.uri))
          (unless (and (fx>= ns 0) (html-tag-name? context.name.local))
            (raise-bad-argument read-html-fragment
                                "context element named in no namespace, SVG or MathML"
                                context.name))
          (let (local (ascii-downcase context.name.local))
            (values ns
                    local
                    (if (fx= ns ns-html) (unchecked-node XMLName local "" "") context.name)
                    context.attributes))))))
  (let (tz (source-tokenizer source read-html-fragment))
    (build-html-fragment tz scripting? ns (html-tokenizer-intern tz local) name attributes)))
