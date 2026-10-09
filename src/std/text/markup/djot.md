# Djot

Parser and HTML renderer for [Djot](https://github.com/jgm/djot/blob/d77f8a0cbea6785c42b3e2b03463195b5ca6f7c7/doc/syntax.md).

To use the bindings from this module:

```scheme
(import :std/text/markup/djot)
```

## string->djot

```scheme
(string->djot string [source-locations: #f]) -> djot-document
```

Parses a string into an abstract syntax tree. With `source-locations: #t`, nodes include [source ranges](#source-locations). Malformed markup follows Djot's literal-text and implicit-closure rules.

```scheme
> (djot->html (string->djot "Hello & welcome.\n"))
"<p>Hello &amp; welcome.</p>\n"
```

## read-djot

```scheme
(read-djot input [source-locations: #f]) -> djot-document
```

Reads and parses a whole document using `:std/io`. Accepts strings, UTF-8 byte vectors, input ports, readers, buffered readers, `#t`/`'stdin`, or file-open argument lists. A string is content, not a pathname: use `(read-djot [path: "input.dj"])` to read a file. Caller-owned ports stay open.

## djot->sxml

```scheme
(djot->sxml document) -> list
```

Returns an SXML (S-expression XML) `(*TOP* ...)` document with unescaped text and symbol names for elements and attributes. Custom attribute spelling, case, and order are preserved. The result can be inspected or transformed with `:std/text/markup/sxml` before printing.

```scheme
> (djot->sxml (string->djot "Hello."))
(*TOP* (p (@) "Hello.") "\n")
```

## djot->html

```scheme
(djot->html document) -> string
```

Renders through the SXML printer in HTML mode without indentation. Non-HTML raw nodes are omitted; math retains its delimiters inside a classed span. Neither renderer modifies the document or emits source locations.

**HTML is not sanitized.** Text and attribute values are escaped, but raw HTML, arbitrary attributes, and URL schemes are allowed. Sanitize untrusted output before serving it.

## write-djot-html

```scheme
(write-djot-html output document)
```

Writes HTML to a `:std/io` output: a writer, buffered writer, port, pathname, file-open arguments, or `#t`/`'stdout`. With `#f` or `'string`, returns a string; with `'u8vector`, returns UTF-8 bytes. HTML is buffered before writing. Caller-owned ports stay open.

```scheme
> (write-djot-html #f (read-djot "Hello."))
"<p>Hello.</p>\n"
```

## Syntax tree

Nodes are transparent typed structs. Constructors, predicates, accessors, and setters are exported. Constructors take inherited fields first. Use `djot-container-children` for child nodes and `djot-textual-text` for text.

A document-level heading starts a section containing the heading and its body. For example, to inspect an attributed heading:

```scheme
> (def document (string->djot "{type=module}\n# Example"))
> (def section (car (djot-container-children document)))
> (def heading (car (djot-container-children section)))
> (djot-heading-level heading)
1
> (def attribute (car (djot-node-attributes heading)))
> (list (djot-attribute-name attribute) (djot-attribute-value attribute))
("type" "module")
```

`attributes` and `auto-attributes` are ordered lists of `djot-attribute`, separating explicit attributes from generated ones. Attribute names, reference keys, and footnote labels are strings; rendering converts element and attribute names to SXML symbols.

Within one attribute specifier, `class=` replaces earlier classes and `.class` appends; stacked specifiers accumulate classes. Quoted values collapse runs of ASCII spaces and line endings but preserve tabs.

| Record | Base | Own fields |
| --- | --- | --- |
| `djot-attribute` | — | `name value`: strings |
| `djot-node` | — | `attributes auto-attributes`: attribute lists; `source`: range or `#f` |
| `djot-container` | `djot-node` | `children`: node list |
| `djot-textual` | `djot-node` | `text`: string |
| `djot-document` | `djot-container` | `references auto-references footnotes`: string-keyed association lists |
| `djot-heading` | `djot-container` | `level`: fixnum, not capped at six |
| `djot-code-block` | `djot-textual` | `language`: string or `#f` |
| `djot-raw-block`, `djot-raw-inline` | `djot-textual` | `format`: string |
| `djot-bullet-list` | `djot-container` | `tight?`: boolean; `style`: marker string |
| `djot-ordered-list` | `djot-container` | `tight?`: boolean; `style`: marker string; `start`: integer |
| `djot-task-list` | `djot-container` | `tight?`: boolean |
| `djot-task-list-item` | `djot-container` | `checked?`: boolean |
| `djot-row` | `djot-container` | `head?`: boolean |
| `djot-cell` | `djot-container` | `head?`: boolean; `alignment`: `default`, `left`, `right`, or `center` |
| `djot-symbol` | `djot-node` | `alias`: string |
| `djot-smart-punctuation` | `djot-textual` | `kind`: punctuation symbol |
| `djot-link`, `djot-image` | `djot-container` | `destination reference`: string or `#f` |
| `djot-reference` | `djot-node` | `label destination`: strings |
| `djot-footnote` | `djot-container` | `label`: string |

These `djot-container` subtypes add no fields: `djot-paragraph`, `djot-section`, `djot-div`, `djot-block-quote`, `djot-list-item`, `djot-definition-list`, `djot-definition-list-item`, `djot-term`, `djot-definition`, `djot-table`, `djot-caption`, `djot-emph`, `djot-strong`, `djot-span`, `djot-mark`, `djot-superscript`, `djot-subscript`, `djot-insert`, `djot-delete`, `djot-double-quoted`, and `djot-single-quoted`.

These `djot-textual` subtypes add no fields: `djot-text`, `djot-verbatim`, `djot-inline-math`, `djot-display-math`, `djot-url`, `djot-email`, and `djot-footnote-reference`. The last stores its label in `text`. `djot-thematic-break`, `djot-soft-break`, `djot-hard-break`, and `djot-nonbreaking-space` inherit directly from `djot-node`.

A table contains a caption followed by rows of cells; an absent caption has no children. A definition-list item contains a term and a definition. Ordered-list styles include the numbering family and delimiters, such as `"1."`, `"(a)"`, or `"I)"`.

Smart-punctuation kinds are `left-single-quote`, `right-single-quote`, `left-double-quote`, `right-double-quote`, `ellipses`, `en-dash`, and `em-dash`. Their `text` retains the original quote, periods, or hyphens. Matched quote pairs use the corresponding container types.

## Source locations

With `source-locations: #t`, nodes with a source span have a `djot-source-range` in `djot-node-source`; otherwise it is `#f`. Its six fixnum fields are `start`, `end`, `start-line`, `start-column`, `end-line`, and `end-column`.

Offsets are zero-based, half-open character ranges in the original string, not byte offsets. Lines and columns are one-based; tabs count as one character. CRLF occupies two characters but advances one line; lone CR and LF each advance one line. An offset just after a line ending has column 1 of the next line.

Ranges span the original input, including across stripped quote/list prefixes. Inline containers include delimiters but exclude following attributes. Paragraphs include their final line ending; text excludes stripped indentation and trailing paragraph whitespace. Document ranges cover the entire input. These are bounding spans, not a lossless syntax tree.

## Headings and references

Only document-level headings create sections; headings inside quotes, divs, lists, and notes do not. A heading of equal or lower level closes the preceding section. A nonempty explicit heading ID and its attributes move to the section. Without an explicit ID, the section receives a generated ID and other attributes stay on the heading.

Generated IDs preserve letters, digits, combining marks, case, `_`, and `-`; whitespace becomes hyphens and punctuation is deleted. IDs use text before smart-punctuation rendering: `a+b` becomes `ab`, `a--b` stays `a--b`, and literal `a—b` becomes `ab`. Collisions receive numeric suffixes; empty results use `s-1`, `s-2`, etc.

Headings also create automatic references. Labels normalize ASCII whitespace without changing case. Explicit definitions override automatic references; link/image attributes override inherited reference attributes. Undefined references render without destinations. Footnotes are numbered by first use and include backlinks.

## DjotResourceError

Parsing and rendering limit nesting to 512 containers, counting paragraphs and generated sections but excluding the document root. Exceeding the limit raises `DjotResourceError`, recognized by `DjotResourceError?`. The error includes its source location and the attempted depth and limit as diagnostic irritants. Rendering checks caller-constructed trees too, including image contents and unused footnotes.

## Compatibility

Compared with djot.js 0.3.2, this implementation follows the linked syntax description for punctuation deletion in heading IDs, retains unattached `^ caption` lines as paragraphs, and trims trailing spaces/tabs from reference URL chunks. Multiline inline-link/image destinations trim spaces/tabs around each line and concatenate; single-line destinations retain their whitespace.
