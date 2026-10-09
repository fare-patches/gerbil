;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Semantic Djot nodes; no delimiter spelling or renderer state.
(import :std/error)
(export (struct-out
  djot-source-range
  djot-attribute
  djot-node
  djot-container
  djot-textual
  djot-document
  djot-paragraph
  djot-section
  djot-div
  djot-block-quote
  djot-list-item
  djot-definition-list
  djot-definition-list-item
  djot-term
  djot-definition
  djot-table
  djot-caption
  djot-emph
  djot-strong
  djot-span
  djot-mark
  djot-superscript
  djot-subscript
  djot-insert
  djot-delete
  djot-double-quoted
  djot-single-quoted
  djot-text
  djot-verbatim
  djot-inline-math
  djot-display-math
  djot-url
  djot-email
  djot-footnote-reference
  djot-thematic-break
  djot-soft-break
  djot-hard-break
  djot-nonbreaking-space
  djot-heading
  djot-code-block
  djot-raw-block
  djot-raw-inline
  djot-bullet-list
  djot-ordered-list
  djot-task-list
  djot-task-list-item
  djot-row
  djot-cell
  djot-symbol
  djot-smart-punctuation
  djot-link
  djot-image
  djot-reference
  djot-footnote)
  DjotResourceError
  DjotResourceError?)

;;; Ranges are zero-based, half-open character offsets into the original input.
;;; Lines and columns are one-based; CRLF is one line ending, two characters.
;;; Attributes are ordered lists of djot-attribute; metadata maps are string-keyed alists.
(defstruct djot-source-range
  ((start        : :fixnum)
   (end          : :fixnum)
   (start-line   : :fixnum)
   (start-column : :fixnum)
   (end-line     : :fixnum)
   (end-column   : :fixnum))
  final: #t)

(defstruct djot-attribute
  ((name : :string) (value : :string))
  final: #t)

(defstruct djot-node
  ((attributes      : :list)
   (auto-attributes : :list)
   (source          :? djot-source-range)))

(defstruct (djot-container djot-node)
  ((children : :list)))

(defstruct (djot-textual djot-node)
  ((text : :string)))

(defstruct (djot-document djot-container)
  ((references      : :list)
   (auto-references : :list)
   (footnotes       : :list))
  final: #t)

(defstruct (djot-paragraph djot-container)
  ()
  final: #t)

(defstruct (djot-section djot-container)
  ()
  final: #t)

(defstruct (djot-div djot-container)
  ()
  final: #t)

(defstruct (djot-block-quote djot-container)
  ()
  final: #t)

(defstruct (djot-list-item djot-container)
  ()
  final: #t)

(defstruct (djot-definition-list djot-container)
  ()
  final: #t)

(defstruct (djot-definition-list-item djot-container)
  ()
  final: #t)

(defstruct (djot-term djot-container)
  ()
  final: #t)

(defstruct (djot-definition djot-container)
  ()
  final: #t)

(defstruct (djot-table djot-container)
  ()
  final: #t)

(defstruct (djot-caption djot-container)
  ()
  final: #t)

(defstruct (djot-emph djot-container)
  ()
  final: #t)

(defstruct (djot-strong djot-container)
  ()
  final: #t)

(defstruct (djot-span djot-container)
  ()
  final: #t)

(defstruct (djot-mark djot-container)
  ()
  final: #t)

(defstruct (djot-superscript djot-container)
  ()
  final: #t)

(defstruct (djot-subscript djot-container)
  ()
  final: #t)

(defstruct (djot-insert djot-container)
  ()
  final: #t)

(defstruct (djot-delete djot-container)
  ()
  final: #t)

(defstruct (djot-double-quoted djot-container)
  ()
  final: #t)

(defstruct (djot-single-quoted djot-container)
  ()
  final: #t)

(defstruct (djot-text djot-textual)
  ()
  final: #t)

(defstruct (djot-verbatim djot-textual)
  ()
  final: #t)

(defstruct (djot-inline-math djot-textual)
  ()
  final: #t)

(defstruct (djot-display-math djot-textual)
  ()
  final: #t)

(defstruct (djot-url djot-textual)
  ()
  final: #t)

(defstruct (djot-email djot-textual)
  ()
  final: #t)

(defstruct (djot-footnote-reference djot-textual)
  ()
  final: #t)

(defstruct (djot-thematic-break djot-node)
  ()
  final: #t)

(defstruct (djot-soft-break djot-node)
  ()
  final: #t)

(defstruct (djot-hard-break djot-node)
  ()
  final: #t)

(defstruct (djot-nonbreaking-space djot-node)
  ()
  final: #t)

(defstruct (djot-heading djot-container)
  ((level : :fixnum))
  final: #t)

(defstruct (djot-code-block djot-textual)
  ((language :? :string))
  final: #t)

(defstruct (djot-raw-block djot-textual)
  ((format : :string))
  final: #t)

(defstruct (djot-raw-inline djot-textual)
  ((format : :string))
  final: #t)

(defstruct (djot-bullet-list djot-container)
  ((tight? : :boolean) (style : :string))
  final: #t)

(defstruct (djot-ordered-list djot-container)
  ((tight? : :boolean)
   (style  : :string)
   (start  : :integer))
  final: #t)

(defstruct (djot-task-list djot-container)
  ((tight? : :boolean))
  final: #t)

(defstruct (djot-task-list-item djot-container)
  ((checked? : :boolean))
  final: #t)

(defstruct (djot-row djot-container)
  ((head? : :boolean))
  final: #t)

(defstruct (djot-cell djot-container)
  ((head? : :boolean) (alignment : :symbol))
  final: #t)

(defstruct (djot-symbol djot-node)
  ((alias : :string))
  final: #t)

(defstruct (djot-smart-punctuation djot-textual)
  ((kind : :symbol))
  final: #t)

(defstruct (djot-link djot-container)
  ((destination :? :string) (reference :? :string))
  final: #t)

(defstruct (djot-image djot-container)
  ((destination :? :string) (reference :? :string))
  final: #t)

(defstruct (djot-reference djot-node)
  ((label : :string) (destination : :string))
  final: #t)

(defstruct (djot-footnote djot-container)
  ((label : :string))
  final: #t)

(deferror-class DjotResourceError ())
