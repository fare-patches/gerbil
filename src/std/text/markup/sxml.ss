;;; -*- Gerbil -*-
;;; (C) vyzo at hackzen.org
;;; Legacy SXML: the printer, SXPath, SXML queries, the SSAX XML reader and
;;; the HTML parser and printer, formerly also exported by
;;; :std/text/markup/xml and :std/text/markup/html. Deprecated: use the
;;; typed :std/text/markup/xml and :std/text/markup/html.
(import :std/deprecation
        ./sxml/print
        ./sxml/sxpath
        ./sxml/sxml-inf
        ./sxml/xml
        ./sxml/html/parser)
(export (import: ./sxml/print)
        (import: ./sxml/sxpath)
        (import: ./sxml/sxml-inf)
        (import: ./sxml/xml)
        (import: ./sxml/html/parser))

(package-deprecation-warning!)
