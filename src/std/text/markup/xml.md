# XML

Typed XML trees, a reader and a writer.

```scheme
(import :std/text/markup/xml)
```

## Nodes

The node types are final structs derived from `XML`, an empty struct that only roots them: `XML?` is true of all of them and of the HTML node types ([HTML](html.md)), but what an element may hold is decided by `xml-node?`, not by `XML?`. Their slots are typed, so a binding of a known node type reads them with dotted access, nested ones included; the generated accessors (`XMLName-local` and the like) are procedures for the same slots.

```scheme
(import :std/text/markup/xml)

(using (doc (read-xml "<!DOCTYPE r SYSTEM 'r.dtd'><r xmlns='urn:x'/>") :- XMLDocument)
  (using (doctype doc.doctype :? XMLDoctype) ; #f without a DOCTYPE
    [doc.root.name.local doc.root.name.uri
     (and doctype doctype.system-id) (and doctype doctype.public-id)]))
;; => ("r" "urn:x" "r.dtd" #f)
```

Nodes are immutable values. After a node is constructed, neither its slots, nor the lists it holds (attributes, children, prolog, epilog, document children), nor the strings reachable from it may be modified, by any thread, including Writer sinks running during a write; nodes may be shared. Modifying a node, its lists or its strings is an error with undefined behaviour. Strings passed to TAL output follow the same rule for the duration of the call.

A node is constructed by applying its type, as in `(XMLName local uri prefix)`, which checks the conditions listed here and raises `ContractViolation` when they do not hold. Each `make-xml-` factory below is its type's constructor, the same procedure as applying the type: `(make-xml-text data)` is `(XMLText data)`, with the same checks and defaults. The HTML factories `make-html-element`, `make-html-attribute` and `make-html-foreign-attribute` are not constructors of the XML types: they check the HTML rules instead ([HTML](html.md#nodes)).

What every reader and writer relies on is that slots hold values of their declared types. The conditions below hold for the trees built by applying the XML types and by `read-xml`. Trees built under the HTML rules (`read-html`, the HTML factories, TAL, Djot) are made of the same structs without those conditions, so neither writer trusts them: `write-xml` checks names, comments and namespace declarations as it writes ([write-xml](#write-xml)), and `write-html` checks what HTML cannot represent ([HTML](html.md#write-html)).

```scheme
(make-xml-name local (uri "") (prefix "")) -> XMLName
(make-xml-attribute name value) -> XMLAttribute
(make-xml-element name attributes children) -> XMLElement
(make-xml-text data) -> XMLText
(make-xml-cdata data) -> XMLCData
(make-xml-comment data) -> XMLComment
(make-xml-pi target data) -> XMLPI
(make-xml-doctype name (public-id #f) (system-id #f)) -> XMLDoctype
(make-xml-document prolog root epilog (doctype #f)) -> XMLDocument
```

- `XMLName`: `local`, a namespace `uri` (`""` for none) and a `prefix` (`""` for none). A prefix needs a namespace; the XML namespace takes the prefix `xml`; names in `xmlns-namespace-uri` only name namespace declarations.
- `(xml-name=? a b)`: same local name and namespace, whatever the prefixes (`equal?` compares prefixes too).
- `XMLAttribute`: a `name` and a string `value`; namespace declarations are attributes named in `xmlns-namespace-uri`.
- `XMLElement`: a `name`, a list of `attributes` with distinct names in document order, and a list of `children` (`xml-node?` values).
- `(xml-element-attribute-value el local (uri ""))`: the value of the attribute named `local` in namespace `uri`, or `#f`.
- `XMLText`, `XMLCData`, `XMLComment`: string `data`. CDATA data cannot contain `]]>`; comment data cannot contain `--` or end with `-`.
- `XMLPI`: an NCName `target` other than `xml` in any ASCII case, and `data` without `?>` that does not start with whitespace.
- `XMLDoctype`: a QName `name` and the `public-id` and `system-id`, each `#f` when absent, without an internal subset. A public identifier requires a system identifier.
- `XMLDocument`: the comments and processing instructions before (`prolog`) and after (`epilog`) the `root` element, and the `doctype` or `#f`.
- `(xml-node? x)`: an element, text, CDATA section, comment or processing instruction: what an element may hold. Names, attributes, doctypes and documents are not.
- `xml-namespace-uri`, `xmlns-namespace-uri`: the reserved namespace URIs.

## read-xml

```scheme
(read-xml source keep-space?: #f keep-comments?: #f) -> XMLDocument
```

Parses a document from a u8vector, a string, an input port or a Reader.

- A u8vector is UTF-8, or US-ASCII or ISO-8859-1 when its XML declaration says so. A UTF-8 byte order mark admits only a UTF-8 or US-ASCII declaration; UTF-16 raises "unsupported encoding (UTF-16)".
- Ports and Readers are read to end of input from their current position, byte ports as bytes and character ports as text. A byte port that characters were already read from (with `read-char` or `peek-char`, so that its character buffer is not empty) is rejected: reading its bytes raises Gambit's "Input port character buffer is not empty" error.
- The XML declaration's version is 1.0 or another 1.x version, read as 1.0, and its encoding name must be well formed for string input too, where it is otherwise ignored.
- CDATA sections become text. Whitespace-only text is dropped unless `keep-space?`; comments are dropped, and the text around them merged, unless `keep-comments?`.
- The DOCTYPE is kept without its internal subset, whose declarations are not processed. Only the predefined entities and character references are expanded: a reference to any other entity raises "invalid reference", even when the internal subset declares it.

Raises `XMLParseError` (an IOError; `xml-parse-error?`) at the first well-formedness or namespace error; at end of input it is also a `PrematureEndOfInput`.
- `XMLParseError-offset` is the byte offset for byte input, even when ISO-8859-1 is decoded, and the character index for string input.
- A lone surrogate in a string (Gambit's port decoders return them for encoded surrogates) is a character XML does not allow.
- Two errors are found before the document is parsed, so they are reported ahead of any earlier error: a lone surrogate in a string, and a non-ASCII byte anywhere after the XML declaration of a document declared US-ASCII.

## write-xml

```scheme
(write-xml node (sink (current-output-port))) -> void
(xml->string node) -> string
(xml->u8vector node) -> u8vector
```

Writes a document or any node as UTF-8 to a Writer or BufferedWriter, a byte port, or a character port.

- Text and attribute values are escaped so that `read-xml` returns them unchanged. CR in CDATA sections, comments, processing instruction data and DOCTYPE identifiers is written as is and reads back as LF.
- The `xmlns` declarations names need are added, and the XML namespace is written with the prefix `xml`; no XML declaration is written.

Raises ContractViolation for:
- a character XML cannot represent;
- a comment with `--` or a final `-`;
- a namespace declaration Namespaces in XML forbids, which trees read by `read-html` can hold, including an attribute named `xmlns` in no namespace (`read-html` makes one from `<html xmlns="…">`), which would read back as a declaration;
- an element whose own `xmlns` declaration contradicts its name's namespace (`read-html` keeps `<svg xmlns="urn:x">`);
- a name that is not an NCName.

It does not check the other conditions of [Nodes](#nodes), such as the data of CDATA sections and processing instructions or distinct attribute names, which a tree may break when built under the HTML rules. When the writer raises, a port sink receives nothing, but a Writer sink may already have received part of the output.

## Differences from the SXML API

- Trees are typed structs instead of lists, and names carry their namespace URI instead of being `uri:local` symbols; there is no `namespaces:` option.
- `read-xml` checks well-formedness (content after the root element, `--` in comments, names, character references, ...), decodes byte input as UTF-8 instead of ISO-8859-1, and does not return the XML declaration as a processing instruction.
- There is no indenting printer and no SXPath; walk trees with dotted access or the accessors.

The SXML implementation remains available, deprecated, as `:std/text/markup/sxml`.
