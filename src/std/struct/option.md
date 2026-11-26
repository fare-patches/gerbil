# Optional values

```scheme
(import :std/struct/option)
```

An option is either `#f` (absent) or `(Some value)` (present). The
payload can itself be `#f`. In a procedure declaration, write
`(opt :? Some)` for a nullable argument and `=> (Maybe Some)` for a
nullable result. In the signatures below, `:t` allows any Scheme value.

## Some and make-Some

```scheme
(Some value) => Some
(make-Some value) => Some
```

Construct a transparent, final struct containing `value`. Use `Some` in
a match pattern to bind the payload, or pass `make-Some` as a procedure.

```scheme
(match (Some #f) ((Some x) (list x))) ;; => (#f)
```

## Some::t

```scheme
Some::t
```

The type descriptor for instances of `Some`.

```scheme
(eq? (class-of (Some 42)) Some::t) ;; => #t
```

## Some?

```scheme
(Some? obj) => :boolean
```

Returns true when `obj` is an instance of `Some`.

```scheme
(Some? (Some #f)) ;; => #t
(Some? #f)        ;; => #f
```

## option?

```scheme
(option? obj) => :boolean
```

Recognizes both forms of an option.

```scheme
(option? (Some #f)) ;; => #t
(option? #f)        ;; => #t
(option? [#f])      ;; => #f
```

## value->option

```scheme
(value->option value (absent #f)) => (Maybe Some)
```

Returns `#f` when `value` and `absent` are `eqv?`. Otherwise returns
`(Some value)`. Use Gerbil’s `absent-value` sentinel when omission and explicit
`#f` have different meanings.

```scheme
(def (setting (value absent-value)) (value->option value absent-value))
(setting)    ;; => #f
(setting #f) ;; => (Some #f)
(setting 42) ;; => (Some 42)
```

## Some-value

```scheme
(Some-value (opt : Some)) => :t
```

Returns the payload of `opt`.

```scheme
(Some-value (Some [])) ;; => ()
```

## option-ref

```scheme
(option-ref (opt :? Some) [default]) => :t
```

Returns the payload of a present option, including a false payload.
For an absent option, returns the supplied default. Omitting the default
or supplying `absent-value` raises a `ContextError` from `option-ref`.

```scheme
(option-ref (Some #f) 'missing) ;; => #f
(option-ref #f 'missing)        ;; => missing
```

## option-get

```scheme
(option-get (opt :? Some)) => :t
```

Equivalent to `(option-ref opt #f)`.

## option-ref/else

```scheme
(option-ref/else (opt :? Some) (default : :procedure := false)) => :t
```

Returns the payload of a present option, including `#f`. For an absent
option, calls the zero-argument procedure `default` and returns its result.
Omitting the procedure gives a fallback of `#f`.

Suppose `cached-setting` returns an option. A cache miss (`#f`) triggers
the database lookup. A cached false setting (`(Some #f)`) returns `#f`
without querying the database.

```scheme
(def (read-setting name)
  (option-ref/else (cached-setting name)
    (lambda () (database-fetch-setting name))))
```

## option->list

```scheme
(option->list (opt :? Some)) => :list
```

Returns a singleton list containing the payload of a `Some`, or the
empty list for `#f`.

```scheme
(option->list (Some #f)) ;; => (#f)
(option->list #f)        ;; => ()
```

## option-map

```scheme
(option-map (f : :procedure) (opt :? Some)) => (Maybe Some)
```

For `(Some x)`, calls `f` on `x` and wraps the result in `Some`.
For `#f`, returns `#f` without calling `f`.

```scheme
(option-map not (Some #t)) ;; => (Some #f)
```

## option-bind

```scheme
(option-bind (opt :? Some) (f : :procedure)) => (Maybe Some)
```

For `(Some x)`, calls `f` on `x` and returns its option directly. The
callback must return a `Some` or `#f`. Any other result raises a contract
violation. For an absent input, returns `#f` without calling `f`.

```scheme
(option-bind (Some #t) not) ;; => #f
```

## option-for-each

```scheme
(option-for-each (f : :procedure) (opt :? Some)) => :void
```

For `(Some x)`, calls `f` once on `x` for effect and discards its result.
For `#f`, skips the call. Both cases return `(void)`.

```scheme
(with-output-to-string
  (lambda () (option-for-each display (Some 42)))) ;; => "42"
```

## option-map/list

```scheme
(option-map/list (f : :procedure) (items : :list)) => (Maybe Some)
```

Applies `f` from left to right. If every call returns a `Some`, returns
a `Some` containing the list of payloads in input order. Empty input
yields `(Some [])`. A callback result of `#f` stops traversal and returns `#f`.
Any other result outside `Some` raises a contract violation.

```scheme
(option-map/list make-Some [1 #f])              ;; => (Some (1 #f))
(option-map/list identity [(Some 1) #f])       ;; => #f
```
