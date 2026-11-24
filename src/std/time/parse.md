# Parsing Temporal instant strings

The `:std/time/parse` module parses date-time strings into the `Instant`s of
`:std/time/instant`, after TC39 Temporal's `Temporal.Instant.from`: RFC 3339
date-times with the ISO 8601 deviations that Temporal allows, followed by
optional RFC 9557 annotations. It is an LL(1) parser over a `BufferedReader`,
built in the style of `:std/text/parser/ll1`. It does all date arithmetic with
exact integers; it does not call `strptime` or `timegm`.

```scheme
(import :std/time/parse)
```

Specifications:

- TC39 Temporal, §13.31 ISO 8601 / RFC 9557 grammar:
  <https://tc39.es/proposal-temporal/#sec-temporal-iso8601grammar>
- RFC 3339, Date and Time on the Internet: Timestamps:
  <https://www.rfc-editor.org/rfc/rfc3339>
- RFC 9557, Date and Time on the Internet: Timestamps with Additional
  Information: <https://www.rfc-editor.org/rfc/rfc9557>
- test262 `Temporal.Instant.from` tests, the source of the test vectors:
  <https://github.com/tc39/test262/tree/main/test/built-ins/Temporal/Instant/from>
- Howard Hinnant, chrono-Compatible Low-Level Date Algorithms
  (`days_from_civil`): <https://howardhinnant.github.io/date_algorithms.html>

## ll1-instant

```text
(ll1-instant (reader : BufferedReader)
             default-offset: (default-offset :? :integer := #f))
  => Instant
```

Parses a `TemporalInstantString` from `reader` and returns its `Instant`, as
`Temporal.Instant.from` does for a string. It consumes the instant and its
annotations and nothing further; use `ll1` from `:std/text/parser/ll1` to parse
a whole string and reject any leftover input.

With `default-offset: #f`, the default, parsing is Temporal-strict: a UTC
offset is required. See [default-offset:](#default-offset) for the extension.

```scheme
(import :std/text/parser/ll1 :std/time/instant :std/time/parse)
(instant-epoch-nanoseconds (ll1 ll1-instant "1976-11-18T15:23:30.123456789Z"))
;; => 217178610123456789
(instant-epoch-seconds (ll1 ll1-instant "2009-02-13T23:31:30+00:00"))
;; => 1234567890
(instant-epoch-nanoseconds (ll1 ll1-instant "1969-12-31T16-08:00[America/Vancouver]"))
;; => 0
(instant-epoch-seconds (ll1 (cut ll1-instant <> default-offset: 3600) "2020-01-01T00:00"))
;; => 1577833200
(ll1 ll1-instant "2020-01-01T00:00")
;; raises ParseError: no UTC offset
```

## Grammar

`ll1-instant` follows the Temporal productions below. Its internal parsers are
named after them: `ll1-date-year`, `ll1-date-month`, `ll1-date-day`,
`ll1-date`, `ll1-hour`, `ll1-minute-second`, `ll1-time-second`,
`ll1-temporal-decimal-fraction`, `ll1-time-spec`, `ll1-utc-offset`,
`ll1-date-time-utc-offset`, `ll1-annotation-value` and `ll1-annotations`.

```text
TemporalInstantString ::= Date DateTimeSeparator Time DateTimeUTCOffset
                          TimeZoneAnnotation? Annotation*
Date              ::= DateYear "-" DateMonth "-" DateDay       (extended)
                    | DateYear DateMonth DateDay               (basic)
DateYear          ::= DIGIT{4} | ("+" | "-") DIGIT{6}          (not "-000000")
DateMonth         ::= "01" .. "12"
DateDay           ::= "01" .. "31"                             (valid for the month)
DateTimeSeparator ::= "T" | "t" | " "
Time              ::= Hour (":" MinuteSecond (":" TimeSecond Fraction?)?)?
                    | Hour (MinuteSecond (TimeSecond Fraction?)?)?
Hour              ::= "00" .. "23"
MinuteSecond      ::= "00" .. "59"
TimeSecond        ::= MinuteSecond | "60"
Fraction          ::= ("." | ",") DIGIT{1,9}
DateTimeUTCOffset ::= "Z" | "z" | UTCOffset(sub-minute)
UTCOffset         ::= Sign Hour
                    | Sign Hour ":" MinuteSecond (":" MinuteSecond Fraction?)?
                    | Sign Hour MinuteSecond (MinuteSecond Fraction?)?
                      (seconds and fraction only with sub-minute precision)
Sign              ::= "+" | "-"
TimeZoneAnnotation ::= "[" "!"? (UTCOffset(minute) | TimeZoneIANAName) "]"
TimeZoneIANAName  ::= Component ("/" Component)*
Component         ::= (ALPHA | "." | "_") (ALPHA | DIGIT | "." | "_" | "-" | "+")*
Annotation        ::= "[" "!"? AnnotationKey "=" AnnotationValue "]"
AnnotationKey     ::= (LOWER | "_") (LOWER | DIGIT | "_" | "-")*
AnnotationValue   ::= ALNUM+ ("-" ALNUM+)*
```

The date, the time and the UTC offset may each independently use the basic
or the extended format, but each must use one of them consistently:
`19761118T15:23:30.1+0000` is valid, `2025-01-01T00:00:00+00:0000` is not.

The parser implements the `TemporalInstantString` grammar.

## Deviations from RFC 3339

Temporal allows these ISO 8601 deviations from RFC 3339, and so does
`ll1-instant`:

- Only calendar dates: no week dates (`2020-W01-1`) or ordinal dates
  (`2020-001`).
- No two-digit years.
- Expanded years of a sign and 6 digits, such as `+275760` or `-009999`;
  `-000000` is invalid.
- Fractions of 1 through 9 digits, on seconds only, not on hours or minutes.
- A space may separate the date and the time.
- Designators may be lowercase: `t`, `z`.
- The decimal separator may be `.` or `,`.
- UTC offsets `-00:00`, `-0000` and `-00` are allowed and mean the same as
  `+00:00`.
- UTC offsets may have seconds and up to 9 fractional digits, such as
  `+00:19:32.37`; the hour-only form `+01` and the basic form `+0100` are
  allowed too.
- Basic or extended format independently for the date, time and offset.
- RFC 9557 suffixes in square brackets.

Following Temporal, the ASCII `-` is the only minus sign: U+2212 MINUS SIGN
is rejected. Offsets of 24 hours or more are rejected.

## Range

The resulting instant must lie within ±10^8^ days of the epoch, from
`-271821-04-20T00:00Z` to `+275760-09-13T00:00Z` inclusive, as for
`Instant`. The check applies after the UTC offset, so
`+275760-09-13T01:00+01:00` is valid and `+275760-09-13T00:00:00.000000001Z`
is not.

## Leap seconds

A second `60` is accepted and read as `59`, as Temporal does:
`2016-12-31T23:59:60Z` is the same instant as `2016-12-31T23:59:59Z`. Instants
are on the POSIX time scale, which does not count leap seconds.

## Annotations

RFC 9557 annotations follow the offset, with the rules of Temporal's
`ParseISODateTime`:

- At most one time zone annotation, either an IANA name such as
  `[Europe/Paris]` or a UTC offset with at most minute precision such as
  `[+01:00]`, and only before any other annotation. It is ignored when
  computing the instant, even when critical (`[!Europe/Vienna]`), and even
  when it disagrees with the UTC offset. The name is checked syntactically
  only. Temporal allows components spelled `.` or `..`, so
  `[America/..]` is valid here. Parsing performs no time zone lookup.
- Calendar annotations `[u-ca=…]` are ignored, whatever the calendar,
  critical or not. Several calendar annotations are rejected if any of them is
  critical.
- Other annotations with a valid lowercase key are ignored, unless critical
  (`[!foo=bar]`), in which case they are rejected.
- Keys are lowercase only: `[U-CA=iso8601]` is rejected.

## default-offset:

`default-offset:` is a Gerbil extension for zone-less input, such as local
timestamps or the output of `strftime` without `%z`. When it is an exact
integer `s` of seconds east of UTC, with |s| < 86400:

- a date-time without a UTC offset is read at offset `s`:
  `2020-01-01T00:00` with `default-offset: 3600` is `2019-12-31T23:00Z`;
- a date without a time is read as midnight at offset `s`: `2020-01-01` and
  `20200101` are accepted;
- a UTC offset in the string wins over `s`;
- a time zone annotation without a UTC offset, as in
  `2020-01-01T00:00[Europe/Paris]`, requires an explicit offset in the string, even
  when a default offset is supplied;
- a date with a UTC offset but no time, such as `2022-09-15Z`, is still
  rejected, as in Temporal.

Other values of `default-offset:` raise `ContractViolation`.

## Errors

Invalid input raises `ParseError` (from `:std/text/parser/base`) with
`ll1-instant` as the location, a message naming the Temporal production that
failed (such as `"DateMonth: out of range"` or
`"TemporalDecimalFraction: more than 9 digits"`), and the offending character
(or `#!eof`) or value as irritant. Invalid dates such as `2021-02-29` and
instants out of range also raise `ParseError`. Under `ll1`, any failure,
including leftover input, is re-raised as a `ParseError` located at `ll1`.

## TODO

Include the input position in parse errors so callers can locate the offending
character even when it appears several times.
