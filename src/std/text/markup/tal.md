# TAL: the Template Attribute Language

HTML templates whose `tal:` attributes hold Gerbil code, after the [Zope Template Attribute Language](https://zope.readthedocs.io/en/latest/zopebook/AppendixC.html). Templates are read and compiled when `define-TAL` expands, through the [HTML tokenizer and the HTML writer](html.md).

```scheme
(import :std/text/markup/tal)
```

## define-TAL

```scheme
(define-TAL (name arg ...) "template")
(define-TAL (name arg ...) string: "template")
(define-TAL (name arg ...) file: "path")
```

Defines a procedure that writes the template, its statements evaluated, to `current-tal-output-port`. Arguments are as in `def`, optional ones `(arg default)` included, but no rest argument. A `file:` path is relative to the source file and read as UTF-8. Expressions in the template see the bindings of the defining module and nothing else: no TAL internals and no HTML module bindings.

```scheme
(define-TAL (items-list title items) #<<EOF
<h1 tal:content="title">Title</h1>
<ul tal:condition="(pair? items)">
  <li tal:repeat="(i items)"
      tal:content="(string-append (number->string (repeat/i.number)) &quot;. &quot; i)">item</li>
</ul>
EOF
)

> (items-list "Fruit & veg" ["apple" "pear"])
<h1>Fruit &amp; veg</h1>
<ul>
  <li>1. apple</li><li>2. pear</li>
</ul>
```

Template errors are syntax errors reported as `path:line:column`, for a string template at its position in the source file; there, lines and columns count template characters, so escapes shift them: a `\n` escape counts as a line break (an error after it is reported on a later line than the source line), and escapes such as `\"` earlier on the same line shift columns.

- Markup must be well nested:
  - An end tag may be left out only for elements whose end tag HTML lets authors omit (`li`, `dt`, `dd`, `p`, `option`, `optgroup`, `tr`, `td`, `th`, `thead`, `tbody`, `tfoot`, `colgroup`, `rb`, `rt`, `rp`, `caption`) and only without `tal:` attributes; a stray, mismatched or void end tag, or an unclosed element, is an error.
  - A start tag on which the parser ends an open `p` (such as `div`, `li`, `table` or `xmp`, unless an element such as `button` or `object` lies between) is an error inside that `p`, except directly inside a `p` without `tal:` attributes, whose end tag it then implies.
  - So is an `li` start tag inside an open `li`, and a `dd` or `dt` inside an open `dd` or `dt`, that the parser would end with the elements inside it: one reached past `address`, `div`, `p` and elements that are not special, such as `span` (`ul`, `table` or `button` stop the search).
  - Inside SVG or MathML content, a start tag on which the parser leaves that content (such as `p` or `div`, or `font` with `color`, `face` or `size`) is an error; integration points such as `foreignObject` and `mi` hold HTML.
  - `plaintext` is an error: the parser would read the rest of the page as its text.
  - A DOCTYPE may only come before elements and text.
- An unknown `tal:` attribute, `tal:content` with `tal:replace`, content for a void element, `tal:attributes` setting `encoding` on MathML `annotation-xml` (it decides how the parser reads the content), `tal:omit-tag` on a raw text element or on an element whose content is read in another context than its own (such as `foreignObject` or `mi`), and markup the HTML writer rejects (see [write-html](html.md#write-html)) are errors. Markup cut off by the end of the template is an error too.
- Of two `tal:` attributes with the same name (ASCII case-insensitively), the first is used and the second ignored.

Static markup is written by the HTML writer: character references are decoded and text re-escaped, `<br/>` becomes `<br>`, attributes without a value are written `name=""`, SVG and MathML names keep their case. A `pre`, `listing` or `textarea` start tag is followed by an LF, which the parser drops, when the element's content starts with one or is not all static. `noscript` content is read as markup. Elements named `tal:...`, such as `<tal:block>`, are not written; their children are.

## Output and errors

- `current-tal-output-port`: the port templates write to; the default is the current output port when the module is loaded. A template writes its whole output there when it returns, or what it rendered so far when it raises (an error that `current-tal:on-error` or a `tal:on-error` handler raises); templates called while another renders join its output.
- `(tal:write thing)`: writes a u8vector as bytes, a string as UTF-8 or anything else as `display` does, in place, and returns `""`.
- `current-tal:on-error`: the handler of an error in a statement outside every `tal:on-error`; by default it writes `ERROR: ` and the escaped error message. The output of the failing statement is discarded first, including what user code wrote to `current-tal-output-port`.

## Statements

An element's statements apply in this order: `tal:define`, `tal:switch`, `tal:condition`, `tal:repeat`, `tal:case`, then the values of `tal:attributes` and `tal:omit-tag`, then `tal:content` or `tal:replace`; `tal:on-error` handles errors of the element's tags and content. A content or replace value fails on its own (the element's tags are kept); any other statement makes the whole element fail.

| statement | value | effect |
|---|---|---|
| `tal:define` | `(var expr) ...`, each optionally after `set!:` or `local:` | Binds each `var` around the rest, left to right; a binding after `set!:` assigns an existing variable instead. |
| `tal:switch` | `expr` | Sets the value `tal:case` compares, for the element's content (dynamically, so templates called inside see it). |
| `tal:case` | `expr` or `else:` | Writes the element when its value is `equal?` to the switch value and no earlier case matched; `else:` when none matched. |
| `tal:condition` | `expr` | Writes the element when the value is true. |
| `tal:repeat` | `(var expr)` | Writes the element once per item of a list, vector, string or anything `:std/iter` iterates, with `var` bound to the item. In its statements and content, `(repeat/var.index)`, `number`, `even?`, `odd?`, `start?`, `end?`, `letter`, `Letter`, `roman` and `Roman` describe the iteration. |
| `tal:content` | `[text: \| as-is: \| raw:] expr` | Replaces the children. `text:` (the default) escapes the value (strings as they are, other values as `display` writes them), `#f` writes nothing and `default:` keeps the template's children. `as-is:` writes the value unescaped. `raw:` writes it unescaped too, but nothing for `#f`, `#!void` and `default:`; use it for expressions that write their output themselves. In `script`, `style` and the other raw text elements, `text:` and `as-is:` values are written as they are (an `as-is:` u8vector decoded as UTF-8) and fail when they would end the element, or an enclosing `noscript`, early; `raw:` output is not checked. |
| `tal:replace` | as `tal:content` | Replaces the element; `default:` keeps it. |
| `tal:attributes` | `(name expr) ...` | Sets attributes: `#f` removes the attribute, `default:` keeps the template's value, `#t` writes `name=""`, any other value is written as text, escaped. Names are matched ASCII case-insensitively and checked when the template compiles. |
| `tal:omit-tag` | `[expr]` | Writes only the children when the value is true or absent; for an expression, the content is checked as if the tags are written (raw text inside an omitted `noscript` still fails on `</noscript`). |
| `tal:on-error` | `[text: \| as-is: \| raw:] expr` or `ignore[:] [expr]` | When the element fails, discards its output and writes the element with the value as its content; with `ignore`, writes only what `expr` writes. `err` is bound to the error. |

Dynamic text, raw text and attribute values must not contain NUL or lone surrogates: such a statement fails.

`raw:` output is written unchecked: nothing checks that it reads back as written where it lands. A template called through `raw:` is checked on its own, as if at the top level, so the elements around the call do not constrain it. In particular, a template whose output may land inside `noscript`, `svg` or `math` must not write user data into `script`, `style` or another raw text element: a scripting parser reads `</noscript>` inside it as the end of the `noscript`, and inside `svg` or `math` that text is read as markup.

## Differences from the SXML TAL

The SXML TAL modules (`:std/text/markup/sxml/tal/...` and `:std/text/markup/sxml/html/tal`) are removed rather than deprecated, and `:std/text/markup/tal` keeps its path with the behavior below.

Templates used to be parsed into SXML and printed by the SXML printer; now:

- Malformed markup is an error instead of being repaired into different elements; `tal:` mistakes are compile errors.
- Static markup is written by the HTML writer (`&copy;` used to be written `&amp;copy;`).
- Statements follow the Zope rules: `tal:replace` with `default:` keeps the element, `raw:` writes no `#!void` or `#f`, `as-is:` with `#f` writes nothing, `tal:attributes` works, repeats over strings work, `tal:define` runs left to right, and `<tal:block>` is not written.
- Templates see only the defining module's bindings, so template variables no longer capture or get captured by TAL's internals (`html-escape` is no longer visible), and `var.repeat` is no longer bound.
- `tal:write` is a procedure.
