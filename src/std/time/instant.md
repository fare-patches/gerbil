# Instant: exact points in time

The `:std/time/instant` module provides `Instant`, an exact point on the time
line counted in nanoseconds since the Unix epoch, after TC39 Temporal's
`Temporal.Instant`, with conversions to and from epoch counts and the
`PreciseTime` of `:std/time/precise`. Parsing Temporal instant strings is in
`:std/time/parse`.

```scheme
(import :std/time/instant)
```

Specifications:

- TC39 Temporal: <https://tc39.es/proposal-temporal/>
- test262 Temporal.Instant tests, the source of the test vectors:
  <https://github.com/tc39/test262/tree/main/test/built-ins/Temporal/Instant>

## Temporal correspondence

| Temporal | Gerbil |
|----------|--------|
| `Temporal.Instant` | `Instant` (struct), `Instant?` |
| `Temporal.Instant.fromEpochNanoseconds(ns)` | `(epoch-nanoseconds->instant ns)` |
| `Temporal.Instant.fromEpochMilliseconds(ms)` | `(epoch-milliseconds->instant ms)` |
| (none) | `(epoch-seconds->instant s)` |
| `instant.epochNanoseconds` | `(instant-epoch-nanoseconds i)` |
| `instant.epochMilliseconds` | `(instant-epoch-milliseconds i)` |
| (none) | `(instant-epoch-seconds i)` |
| `Temporal.Now.instant()` | `(current-instant)` |
| `Temporal.Instant.compare(a, b)` | `(instant-compare a b)` |
| `instant.equals(other)` | `(instant=? a b)` |
| (none) | `(instant->precise-time i)`, `(precise-time->instant p)` |

For string input, see `:std/time/parse`.

## Time scale

An `Instant` is an exact integer count of nanoseconds since
1970-01-01T00:00:00Z on the POSIX time scale: every day has exactly 86400
seconds and leap seconds are not counted, as in Temporal, `time_t` and
`clock_gettime(CLOCK_REALTIME)`.

## Range

Gerbil accepts arbitrary-precision exact integer epoch counts. The numeric constructors
raise a contract violation for other values, including integral flonums.
The Temporal string parser enforces Temporal's inclusive ±10^8^ day range.
Conversion to a native timespec checks the platform's seconds range.

## Flooring

Conversions to coarser units floor toward negative infinity, as Temporal's
`epochMilliseconds` does: -1 ns is -1 ms and -1 s, not 0. Likewise
`instant->precise-time` keeps `tv_nsec` in [0, 10^9^), so -1 ns is
`tv_sec = -1`, `tv_nsec = 999999999`.

## Relation to Time and PreciseTime

`:std/time/time` and `:std/time/precise` define `Time`, `ExactTime`,
`InexactTime`, `CoarseTime` and `PreciseTime`, which wrap a flonum or an
opaque `timeval`/`timespec`. They are kept unchanged for backward
compatibility. `Instant` is the canonical exact representation of a point in
time: it is an ordinary transparent struct, so `equal?` compares instants and
they print readably, and it is not a subtype of `Time`.

## Instant

```text
(defstruct Instant ((epoch-nanoseconds : :integer))
  transparent: #t
  acyclic: #t
  final: #t)
```

The only field is the epoch nanoseconds. The constructor accepts an exact integer.

## epoch-nanoseconds->instant

```text
(epoch-nanoseconds->instant (ns : :integer))
  => Instant
```

Returns the instant `ns` nanoseconds after the epoch.

## epoch-milliseconds->instant

```text
(epoch-milliseconds->instant (ms : :integer))
  => Instant
```

Returns the instant `ms` milliseconds after the epoch.

## epoch-seconds->instant

```text
(epoch-seconds->instant (s : :integer))
  => Instant
```

Returns the instant `s` seconds after the epoch.

## instant-epoch-nanoseconds

```text
(instant-epoch-nanoseconds (i : Instant))
  => :integer
```

Returns the epoch nanoseconds of `i`.

## instant-epoch-milliseconds

```text
(instant-epoch-milliseconds (i : Instant))
  => :integer
```

Returns the epoch milliseconds of `i`, floored.

## instant-epoch-seconds

```text
(instant-epoch-seconds (i : Instant))
  => :integer
```

Returns the epoch seconds of `i`, floored.

## current-instant

```text
(current-instant)
  => Instant
```

Returns the current instant of the realtime clock, read with
`current-time-precise`. It follows wall-clock steps, so successive readings
can go backwards when the system clock is set.

## instant-compare

```text
(instant-compare (a : Instant)
                 (b : Instant))
  => :fixnum
```

Returns -1, 0 or 1 as `a` is before, at or after `b`.

## instant=?

```text
(instant=? (a : Instant)
           (b : Instant))
  => :boolean
```

Returns whether `a` and `b` are the same instant; same as `equal?`.

## instant->precise-time

```text
(instant->precise-time (i : Instant))
  => PreciseTime
```

Returns a fresh `PreciseTime` whose `timespec` holds the floored seconds of
`i` and the remaining nanoseconds in [0, 10^9^).

## precise-time->instant

```text
(precise-time->instant (p : PreciseTime))
  => Instant
```

Returns the instant `tv_sec × 10^9^ + tv_nsec` of `p`.

## Constructing a PreciseTime

`(seconds+nseconds->precise-time seconds nanoseconds)` in `:std/time/precise`
takes whole POSIX seconds and a nanosecond offset from 0 through 999999999.
It raises a contract violation for an invalid offset or seconds outside the
platform's supported range. For example, one nanosecond before the epoch is
`(seconds+nseconds->precise-time -1 999999999)`.

## TODO

Add an RFC 9557 formatter for UTC output. Define the supported range and
how the formatter reports an instant outside it.
