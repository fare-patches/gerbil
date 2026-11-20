# HTML

Typed HTML trees, a reader that parses as the WHATWG HTML standard specifies, and a writer that only writes what the parser reads back.

```scheme
(import :std/text/markup/xml :std/text/markup/html)
```

## Nodes

HTML trees are built from the node types of [`:std/text/markup/xml`](xml.md): elements, text, comments and processing instructions, read with dotted access or its accessors. This module adds raw markup, the DOCTYPE and the document: `HTMLRaw`, `HTMLDoctype` and `HTMLDocument`, final structs derived from `XML` like the XML node types. `HTMLDoctype` is not `XMLDoctype`: their names and identifiers follow different rules. HTML elements and their attributes are named in no namespace; the parser names SVG and MathML elements in `svg-namespace-uri` and `mathml-namespace-uri`, and their `xlink:`, `xml:` and `xmlns` attributes in the XLink, XML and XMLNS namespaces (`xlink-namespace-uri`). Nodes are immutable values, as [`:std/text/markup/xml`](xml.md#nodes) describes. `make-html-raw`, `make-html-doctype` and `make-html-document` are the constructors of `HTMLRaw`, `HTMLDoctype` and `HTMLDocument`, the same procedures as applying the types, as the `make-xml-` factories are of the XML types. `make-html-element`, `make-html-attribute` and `make-html-foreign-attribute` are not the same as applying `XMLElement` or `XMLAttribute`, which check the XML rules: they check the HTML rules below, and the element or attribute they return need not meet the XML ones.

```scheme
(make-html-element name attributes children namespace: "") -> XMLElement
(make-html-attribute name value) -> XMLAttribute
(make-html-foreign-attribute qname value) -> XMLAttribute
(make-html-raw data) -> HTMLRaw
(make-html-doctype name (public-id #f) (system-id #f)) -> HTMLDoctype
(make-html-document children) -> HTMLDocument
```

- `make-html-element`: `namespace` is `""`, `svg-namespace-uri` or `mathml-namespace-uri`; `name` is a tag name the parser reads back (lower case, except the SVG names it adjusts, such as `foreignObject`; not `image` in the HTML namespace, which the parser reads as `img`); `svg` and `math` only in their own namespaces. Attributes are in no namespace (`make-html-attribute`), or on SVG and MathML elements the namespaced ones `make-html-foreign-attribute` builds; on SVG and MathML elements, names in no namespace are spelled as the parser adjusts them (`viewBox`, not `viewbox`). Attribute names must be distinct after ASCII case folding. Children are `html-node?` values.
- `make-html-attribute`: an attribute in no namespace; `name` follows the HTML syntax (`html-attribute-name?`) and has no ASCII upper case, except in the SVG and MathML spellings the parser adjusts names to (`viewBox`, `definitionURL`), valid on those elements only.
- `make-html-foreign-attribute`: a namespaced attribute of an SVG or MathML element by its written name: `xlink:actuate`, `xlink:arcrole`, `xlink:href`, `xlink:role`, `xlink:show`, `xlink:title`, `xlink:type`, `xml:lang`, `xml:space`, `xmlns`, `xmlns:xlink`.
- `HTMLRaw`: markup `data` written as is, unchecked.
- `HTMLDoctype`: a `name` without whitespace, `>`, NUL or upper case, not empty when there are identifiers, and the `public-id` and `system-id`, each `#f` when absent, without `>`, NUL or both quote characters.
- `HTMLDocument`: its `children` in document order, with at most one DOCTYPE, after only comments and processing instructions. `(html-document-doctype doc)` returns that DOCTYPE or `#f`.
- `(html-node? x)`: an element, text, comment, processing instruction or `HTMLRaw`: what an element or document may hold, besides the document's DOCTYPE. `(html-tag-name? str)` and `(html-attribute-name? str)` test names.

```scheme
(import :std/text/markup/xml :std/text/markup/html)

(using ((doc (read-html "<!DOCTYPE html><p class=x>a") :- HTMLDocument)
        (doctype (html-document-doctype doc) :? HTMLDoctype)
        (html (cadr doc.children) :- XMLElement))
  [(and doctype doctype.public-id) html.name.local (length html.children)])
;; => (#f "html" 2)
```

## read-html

```scheme
(read-html source scripting?: #t) -> HTMLDocument
(read-html-fragment source context: "body" scripting?: #t) -> list
```

Parse a u8vector of UTF-8, a string, an input port or a Reader, as browsers do: missing `html`, `head` and `body` elements are created, end tags implied, misnested markup recovered and character references decoded. Malformed markup is never an error.

- Ports and Readers are read to end of input from their current position. A leading byte order mark in byte input is skipped. A lone surrogate in a string reads as U+FFFD. A byte port that characters were already read from is rejected, as for [`read-xml`](xml.md).
- The document holds the DOCTYPE, if any, and the `html` element among the comments and processing instructions around it. SVG and MathML elements are named in their namespaces. The contents of a `template` element are its children.
- With `scripting?` set, as in browsers, `noscript` content is raw text.
- `HTMLParseError` (an IOError; `html-parse-error?`, `HTMLParseError-offset`) is raised for invalid UTF-8 in byte input and for nesting deeper than 512. The offset is a byte offset in byte input and a character index in string input.

Nesting is limited as Go's `x/net/html` limits it:
- The error is raised at the tag (end tags open elements too) or other token that would make the stack of open elements longer than 512 entries, or the list of active formatting elements and markers longer than 512.
- Text in a table, which reopens formatting elements when the token after it is read, is reported where it starts.
- The stack counts `html` (in a fragment, a synthetic `html` root), so 510 nested `div` elements fill it inside `body`, and 511 in a fragment.
- Misnested formatting elements, which the parser moves, can still nest deeper in the tree.

`read-html-fragment` parses as the content of a context element, as `innerHTML` does, and returns the nodes. `context` is an HTML tag name or an `XMLElement` (the only way to give an SVG or MathML context); `"template"` accepts any content, including table rows and cells.

## write-html

```scheme
(write-html node (sink (current-output-port)) scripting?: #t) -> void
(html->string node scripting?: #t) -> string
(html->u8vector node scripting?: #t) -> u8vector
(html-escape str) -> string
```

Writes an `HTMLDocument`, a node, or a list of nodes (a fragment, written in order) as UTF-8 to a Writer or BufferedWriter, a byte port, or a character port (as characters).

Output:
- Elements, SVG and MathML ones included, have end tags, except the void elements (`area base br col embed hr img input link meta source track wbr basefont bgsound frame keygen param`), which must have no children.
- Text escapes `& < >`; attribute values are double-quoted and escape `& < > "`; NBSP, TAB, LF and CR are written as they are. An empty value is written `name=""`.
- The text of `script`, `style`, `xmp`, `iframe`, `noembed`, `noframes`, `plaintext` and (with `scripting?`) `noscript` is written literally; that of `title` and `textarea` escaped. These elements take text only.
- A newline is added after the start tag of `pre`, `listing` and `textarea` when their text (after any empty text nodes) starts with LF or CR, as the parser drops one there.
- A `plaintext` element must be the last node written: the end tags after it are left out, as the parser reads everything after its start tag as its text.
- `HTMLRaw` is written as is, unchecked. The DOCTYPE is written like `<!DOCTYPE html PUBLIC "id" "id">`.

The writer raises ContractViolation for what the parser would not read back as written (among trees that meet the [node contract](xml.md#nodes)), so that data never becomes markup:
- element names that are not lower case HTML tag names (SVG names as the parser adjusts them, such as `foreignObject`), and `image` in the HTML namespace, which the parser reads as `img`;
- prefixed elements, and elements in a namespace other than HTML, SVG and MathML;
- an element in another namespace than the parser gives its start tag under its parent (an HTML `script` in SVG, a `div` in SVG), not checked for the top-level elements of the node written;
- `svg` and `math` elements in the HTML namespace anywhere, and at the top level in any namespace other than their own;
- at the top level, and below it outside a nested `svg` or `math`, foreign elements named like HTML raw text, RCDATA or `noscript` elements whose content would end them early when the output is parsed in an HTML context;
- raw text, `plaintext` and (with `scripting?`) `noscript` elements in or after a `frameset` (except `noframes`) or after a `col` child of a `template`, where the parser ignores their start tags;
- attribute names with whitespace, `/`, `>` or NUL, or with `=` after the first character, names with ASCII upper case on HTML elements, and two attributes whose names are equal (the parser keeps the first);
- attributes in a namespace on HTML elements, and on SVG and MathML elements in any namespace but the `xlink:`, `xml:` and `xmlns` names the parser makes; in no namespace, foreign attribute names the tree builder rewrites (`viewbox` or `FOO` on an SVG element);
- NUL and lone surrogates in text, attribute values and comments, and lone surrogates in processing instruction data (which keeps NUL, as the tokenizer does);
- raw text containing its end tag (`</style` followed by whitespace, `/` or `>`), and script text that would not end at the `</script>` written after it (it ends early, or at the end of input in the script double escaped state);
- comments starting with `>` or `->` or containing `-->` or `--!>`;
- processing instruction targets other than an ASCII letter or `_` followed by letters, digits, `-` and `_`, the targets `xml` and `xml-stylesheet`, and data with `>` or leading whitespace;
- with `scripting?` unset, comments, processing instructions and literal text inside `noscript` containing `</noscript`, and `noscript` elements (in any namespace) inside `noscript`.

Limits of the round trip:
- A tree read with `scripting?: #f` must be written with `scripting?: #f`.
- Trees nested deeper than `read-html` accepts are written, but reading them back raises `HTMLParseError`.
- CR reads back as LF.
- A DOCTYPE keeps its name and identifiers only. One that put the document in quirks mode for being malformed (such as `<!DOCTYPE html PUBLIC>`) is written as a well-formed one, so the document may read back in no-quirks mode, with another structure.
- The parser may restructure trees it would not produce itself (a `p` inside a `p`, text in a table, a `template`'s children): the writer checks what each node is read back as, not where the tree builder puts it.

When the writer raises, a port sink receives nothing, but a Writer sink may already have received part of the output.

`html-escape` escapes `& < > " '` as `&amp; &lt; &gt; &quot; &#39;` and returns `str` itself when nothing needs escaping.

## Conformance

The reader and writer are checked against the html5lib tokenizer tests and the WPT tree construction tests, which are not in this tree. [`html-conformance.ss`](html-conformance.ss) runs them from local checkouts: its header gives the pinned revisions and the commands to fetch them, compile it and run it. It also writes each tree with `write-html` and reads it back, and lists the tests it skips, with the reason; it fails when a test fails or the skipped tests change.

```sh
out=$(mktemp -d)
gxc -O -exe -d "$out" -o "$out/html-conformance" src/std/text/markup/html-conformance.ss
"$out/html-conformance" html5lib-tests wpt
```

## Differences from the SXML API

- `read-html` builds the standard tree (implied elements and end tags, all character references decoded, adjacent text merged) where `html->sxml` kept the markup's structure.
- The void and raw text elements are fixed by the standard: there are no `current-html-void-tags` and `current-html-raw-tags` parameters.
- `sxml->html` wrote any tree; `write-html` rejects trees that would not read back.
- There is no `html-strip`.

The SXML implementation remains available, deprecated, as `:std/text/markup/sxml`.
