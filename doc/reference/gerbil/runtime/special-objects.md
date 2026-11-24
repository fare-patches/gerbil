# Special Objects

## absent-obj
```
(def absent-obj)
```

Gambit primitives use `#!absent` to signal an omitted optional argument.
Take care when using it as a parameter default in Gerbil. For example:

```scheme
(def (received x) (eq? x absent-obj))
(def (forward (x absent-obj)) (received x))
```

When loaded from source, `(forward)` raises a wrong-arity error: the
interpreter treats the forwarded argument as missing. Compiling the same
module with `gxc` gives `#t`. Even a procedure that only compares its
optional parameter with `eq?` can encounter this problem. Use
`absent-value` for an omission marker in Gerbil code.

## absent-value
```
(def absent-value)
```

Gerbil uses this sentinel for missing hash entries and omitted keyword
arguments. It is an ordinary value that can be passed between procedures
in both interpreted and compiled code. Use it when `#f` is a valid
argument and omission has a different meaning. Passing `absent-value`
explicitly to a keyword parameter selects its default.

See [`value->option`](https://git.cons.io/mighty-gerbils/gerbil/src/branch/v0.19-staging/src/std/struct/option.md)
for an example that distinguishes omission from an explicit `#f`.

## true
``` scheme
(true . args) -> #t
```

Returns `#t`, ignoring its arguments.

## true?
``` scheme
(true? obj) -> boolean

  obj := any object
```

Returns true if the object is `#t`.

## false
``` scheme
(false . args) -> #f
```

Returns `#f`, ignoring its arguments.

## void
``` scheme
(void . args) -> #!void
```

Returns `#!void`, ignoring its arguments

## void?
``` scheme
(void? obj) -> boolean
```

Returns true if the object *obj* is `#!void`.

## eof-object
``` scheme
(eof-object . args)
```

Returns the eof object, ignoring its arguments.

## identity
``` scheme
(identity x) -> x

  x := any value
```

The identity function, eg. returns anything passed to it.

## dssl-object?
``` scheme
(dssl-object? obj) -> boolean

  obj := any object
```

Returns true if the object is a DSSL syntactic token.

## dssl-key-object?
``` scheme
(dssl-key-object? obj) -> boolean

  obj := any object
```

Returns true if the object is `#!key`.

## dssl-rest-object?
``` scheme
(dssl-rest-object? obj) -> boolean

  obj := any object
```

Returns true if the object is `#!rest`.

## dssl-optional-object?
``` scheme
(dssl-optional-object? obj) -> boolean

  obj := any object
```

Returns true if the object is `#!optional`.

## immediate?
``` scheme
(immediate? obj) -> boolean

  obj := any object
```

Returns true if the object *obj* is an immediate value.
