(declare (block) (standard-bindings) (extended-bindings))
(begin
  (define gerbil/runtime/mop-system-classes::timestamp 1795039814)
  (begin
    (declare
      (not optimize-dead-definitions
           builtin::t
           subtyped::t
           structure::t
           immediate::t
           special::t
           atom::t
           char::t
           boolean::t
           true::t
           false::t
           eof::t
           void::t
           unbound::t
           unbound2::t
           dssl-token::t
           optional::t
           rest::t
           key::t
           number::t
           real::t
           integer::t
           fixnum::t
           bignum::t
           ratnum::t
           flonum::t
           stflonum::t
           haflonum::t
           cpxnum::t
           symbolic::t
           symbol::t
           keyword::t
           list::t
           pair::t
           null::t
           sequence::t
           vector::t
           string::t
           hvector::t
           u8vector::t
           s8vector::t
           u16vector::t
           s16vector::t
           u32vector::t
           s32vector::t
           u64vector::t
           s64vector::t
           f32vector::t
           f64vector::t
           values::t
           box::t
           frame::t
           continuation::t
           promise::t
           weak::t
           foreign::t
           procedure::t
           return::t))
    (define builtin::t
      (let ((__tmp149380 (cons t::t '())))
        (declare (not safe))
        (__make-system-class 'builtin __tmp149380 '())))
    (define subtyped::t
      (let ((__tmp149381 (cons builtin::t '())))
        (declare (not safe))
        (__make-system-class 'subtyped __tmp149381 '())))
    (define structure::t
      (let ((__tmp149382 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'structure __tmp149382 '())))
    (define immediate::t
      (let ((__tmp149383 (cons builtin::t '())))
        (declare (not safe))
        (__make-system-class 'immediate __tmp149383 '((acyclic: . #t)))))
    (define special::t
      (let ((__tmp149384 (cons immediate::t '())))
        (declare (not safe))
        (__make-system-class 'special __tmp149384 '((acyclic: . #t)))))
    (define atom::t
      (let ((__tmp149385 (cons special::t '())))
        (declare (not safe))
        (__make-system-class 'atom __tmp149385 '((acyclic: . #t)))))
    (define char::t
      (let ((__tmp149386 (cons special::t '())))
        (declare (not safe))
        (__make-system-class 'char __tmp149386 '((acyclic: . #t)))))
    (define boolean::t
      (let ((__tmp149387 (cons special::t '())))
        (declare (not safe))
        (__make-system-class 'boolean __tmp149387 '((acyclic: . #t)))))
    (define true::t
      (let ((__tmp149388 (cons boolean::t (cons atom::t '()))))
        (declare (not safe))
        (__make-system-class 'true __tmp149388 '((acyclic: . #t)))))
    (define false::t
      (let ((__tmp149389 (cons boolean::t (cons atom::t '()))))
        (declare (not safe))
        (__make-system-class 'false __tmp149389 '((acyclic: . #t)))))
    (define eof::t
      (let ((__tmp149390 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'eof __tmp149390 '((acyclic: . #t)))))
    (define void::t
      (let ((__tmp149391 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'void __tmp149391 '((acyclic: . #t)))))
    (define unbound::t
      (let ((__tmp149392 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'unbound __tmp149392 '((acyclic: . #t)))))
    (define unbound2::t
      (let ((__tmp149393 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'unbound2 __tmp149393 '((acyclic: . #t)))))
    (define unused::t
      (let ((__tmp149394 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'unused __tmp149394 '((acyclic: . #t)))))
    (define deleted::t
      (let ((__tmp149395 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'deleted __tmp149395 '((acyclic: . #t)))))
    (define absent::t
      (let ((__tmp149396 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'absent __tmp149396 '((acyclic: . #t)))))
    (define dssl-token::t
      (let ((__tmp149397 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'dssl-token __tmp149397 '((acyclic: . #t)))))
    (define optional::t
      (let ((__tmp149398 (cons dssl-token::t '())))
        (declare (not safe))
        (__make-system-class 'optional __tmp149398 '((acyclic: . #t)))))
    (define rest::t
      (let ((__tmp149399 (cons dssl-token::t '())))
        (declare (not safe))
        (__make-system-class 'rest __tmp149399 '((acyclic: . #t)))))
    (define key::t
      (let ((__tmp149400 (cons dssl-token::t '())))
        (declare (not safe))
        (__make-system-class 'key __tmp149400 '((acyclic: . #t)))))
    (define unknown::t
      (let ((__tmp149401 (cons atom::t '())))
        (declare (not safe))
        (__make-system-class 'unknown __tmp149401 '((acyclic: . #t)))))
    (define number::t
      (let ((__tmp149402 (cons builtin::t '())))
        (declare (not safe))
        (__make-system-class 'number __tmp149402 '((acyclic: . #t)))))
    (define real::t
      (let ((__tmp149403 (cons number::t '())))
        (declare (not safe))
        (__make-system-class 'real __tmp149403 '((acyclic: . #t)))))
    (define integer::t
      (let ((__tmp149404 (cons real::t '())))
        (declare (not safe))
        (__make-system-class 'integer __tmp149404 '((acyclic: . #t)))))
    (define fixnum::t
      (let ((__tmp149405 (cons integer::t (cons immediate::t '()))))
        (declare (not safe))
        (__make-system-class 'fixnum __tmp149405 '((acyclic: . #t)))))
    (define bignum::t
      (let ((__tmp149406 (cons integer::t (cons subtyped::t '()))))
        (declare (not safe))
        (__make-system-class 'bignum __tmp149406 '((acyclic: . #t)))))
    (define ratnum::t
      (let ((__tmp149407 (cons real::t (cons subtyped::t '()))))
        (declare (not safe))
        (__make-system-class 'ratnum __tmp149407 '((acyclic: . #t)))))
    (define flonum::t
      (let ((__tmp149408 (cons real::t '())))
        (declare (not safe))
        (__make-system-class 'flonum __tmp149408 '((acyclic: . #t)))))
    (define stflonum::t
      (let ((__tmp149409 (cons flonum::t (cons immediate::t '()))))
        (declare (not safe))
        (__make-system-class 'stflonum __tmp149409 '((acyclic: . #t)))))
    (define haflonum::t
      (let ((__tmp149410 (cons flonum::t (cons subtyped::t '()))))
        (declare (not safe))
        (__make-system-class 'haflonum __tmp149410 '((acyclic: . #t)))))
    (define cpxnum::t
      (let ((__tmp149411 (cons number::t (cons subtyped::t '()))))
        (declare (not safe))
        (__make-system-class 'cpxnum __tmp149411 '((acyclic: . #t)))))
    (define symbolic::t
      (let ((__tmp149412 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'symbolic __tmp149412 '((acyclic: . #t)))))
    (define symbol::t
      (let ((__tmp149413 (cons symbolic::t '())))
        (declare (not safe))
        (__make-system-class 'symbol __tmp149413 '((acyclic: . #t)))))
    (define keyword::t
      (let ((__tmp149414 (cons symbolic::t '())))
        (declare (not safe))
        (__make-system-class 'keyword __tmp149414 '((acyclic: . #t)))))
    (define list::t
      (let ((__tmp149415 (cons builtin::t '())))
        (declare (not safe))
        (__make-system-class 'list __tmp149415 '())))
    (define pair::t
      (let ((__tmp149416 (cons list::t (cons subtyped::t '()))))
        (declare (not safe))
        (__make-system-class 'pair __tmp149416 '())))
    (define null::t
      (let ((__tmp149417 (cons list::t (cons atom::t '()))))
        (declare (not safe))
        (__make-system-class 'null __tmp149417 '((acyclic: . #t)))))
    (define sequence::t
      (let ((__tmp149418 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'sequence __tmp149418 '())))
    (define vector::t
      (let ((__tmp149419 (cons sequence::t '())))
        (declare (not safe))
        (__make-system-class 'vector __tmp149419 '())))
    (define string::t
      (let ((__tmp149420 (cons sequence::t '())))
        (declare (not safe))
        (__make-system-class 'string __tmp149420 '((acyclic: . #t)))))
    (define hvector::t
      (let ((__tmp149421 (cons sequence::t '())))
        (declare (not safe))
        (__make-system-class 'hvector __tmp149421 '((acyclic: . #t)))))
    (define u8vector::t
      (let ((__tmp149422 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 'u8vector __tmp149422 '((acyclic: . #t)))))
    (define s8vector::t
      (let ((__tmp149423 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 's8vector __tmp149423 '((acyclic: . #t)))))
    (define u16vector::t
      (let ((__tmp149424 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 'u16vector __tmp149424 '((acyclic: . #t)))))
    (define s16vector::t
      (let ((__tmp149425 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 's16vector __tmp149425 '((acyclic: . #t)))))
    (define u32vector::t
      (let ((__tmp149426 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 'u32vector __tmp149426 '((acyclic: . #t)))))
    (define s32vector::t
      (let ((__tmp149427 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 's32vector __tmp149427 '((acyclic: . #t)))))
    (define u64vector::t
      (let ((__tmp149428 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 'u64vector __tmp149428 '((acyclic: . #t)))))
    (define s64vector::t
      (let ((__tmp149429 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 's64vector __tmp149429 '((acyclic: . #t)))))
    (define f32vector::t
      (let ((__tmp149430 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 'f32vector __tmp149430 '((acyclic: . #t)))))
    (define f64vector::t
      (let ((__tmp149431 (cons hvector::t '())))
        (declare (not safe))
        (__make-system-class 'f64vector __tmp149431 '((acyclic: . #t)))))
    (define hunk::t
      (let ((__tmp149432 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'hunk __tmp149432 '())))
    (define values::t
      (let ((__tmp149433 (cons hunk::t (cons sequence::t '()))))
        (declare (not safe))
        (__make-system-class 'values __tmp149433 '())))
    (define box::t
      (let ((__tmp149434 (cons hunk::t '())))
        (declare (not safe))
        (__make-system-class 'box __tmp149434 '())))
    (define frame::t
      (let ((__tmp149435 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'frame __tmp149435 '())))
    (define continuation::t
      (let ((__tmp149436 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'continuation __tmp149436 '())))
    (define promise::t
      (let ((__tmp149437 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'promise __tmp149437 '())))
    (define weak::t
      (let ((__tmp149438 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'weak __tmp149438 '())))
    (define foreign::t
      (let ((__tmp149439 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'foreign __tmp149439 '((acyclic: . #t)))))
    (define procedure::t
      (let ((__tmp149440 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'procedure __tmp149440 '())))
    (define return::t
      (let ((__tmp149441 (cons subtyped::t '())))
        (declare (not safe))
        (__make-system-class 'return __tmp149441 '())))
    (define time::t
      (let ((__tmp149442 (macro-type-time)))
        (declare (not safe))
        (__shadow-class__% __tmp149442 '((acyclic: . #t)))))
    (define thread::t
      (let ((__tmp149443 (macro-type-thread)))
        (declare (not safe))
        (__shadow-class__% __tmp149443 '())))
    (define thread-group::t
      (let ((__tmp149444 (macro-type-tgroup)))
        (declare (not safe))
        (__shadow-class__% __tmp149444 '())))
    (define mutex::t
      (let ((__tmp149445 (macro-type-mutex)))
        (declare (not safe))
        (__shadow-class__% __tmp149445 '())))
    (define condvar::t
      (let ((__tmp149446 (macro-type-condvar)))
        (declare (not safe))
        (__shadow-class__% __tmp149446 '())))
    (define port::t
      (let ((__tmp149447 (macro-type-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149447 '())))
    (define object-port::t
      (let ((__tmp149448 (macro-type-object-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149448 '())))
    (define character-port::t
      (let ((__tmp149449 (macro-type-character-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149449 '())))
    (define byte-port::t
      (let ((__tmp149450 (macro-type-byte-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149450 '())))
    (define device-port::t
      (let ((__tmp149451 (macro-type-device-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149451 '())))
    (define vector-port::t
      (let ((__tmp149452 (macro-type-vector-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149452 '())))
    (define string-port::t
      (let ((__tmp149453 (macro-type-string-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149453 '())))
    (define u8vector-port::t
      (let ((__tmp149454 (macro-type-u8vector-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149454 '())))
    (define raw-device-port::t
      (let ((__tmp149455 (macro-type-raw-device-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149455 '())))
    (define tcp-server-port::t
      (let ((__tmp149456 (macro-type-tcp-server-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149456 '())))
    (define udp-port::t
      (let ((__tmp149457 (macro-type-udp-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149457 '())))
    (define directory-port::t
      (let ((__tmp149458 (macro-type-directory-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149458 '())))
    (define event-queue-port::t
      (let ((__tmp149459 (macro-type-event-queue-port)))
        (declare (not safe))
        (__shadow-class__% __tmp149459 '())))
    (define table::t
      (let ((__tmp149460 (macro-type-table)))
        (declare (not safe))
        (__shadow-class__% __tmp149460 '())))
    (define readenv::t
      (let ((__tmp149461 (macro-type-readenv)))
        (declare (not safe))
        (__shadow-class__% __tmp149461 '())))
    (define writeenv::t
      (let ((__tmp149462 (macro-type-writeenv)))
        (declare (not safe))
        (__shadow-class__% __tmp149462 '())))
    (define readtable::t
      (let ((__tmp149463 (macro-type-readtable)))
        (declare (not safe))
        (__shadow-class__% __tmp149463 '())))
    (define processor::t
      (let ((__tmp149464 (macro-type-processor)))
        (declare (not safe))
        (__shadow-class__% __tmp149464 '())))
    (define vm::t
      (let ((__tmp149465 (macro-type-vm)))
        (declare (not safe))
        (__shadow-class__% __tmp149465 '())))
    (define file-info::t
      (let ((__tmp149466 (macro-type-file-info)))
        (declare (not safe))
        (__shadow-class__% __tmp149466 '((acyclic: . #t)))))
    (define socket-info::t
      (let ((__tmp149467 (macro-type-socket-info)))
        (declare (not safe))
        (__shadow-class__% __tmp149467 '((acyclic: . #t)))))
    (define address-info::t
      (let ((__tmp149468 (macro-type-address-info)))
        (declare (not safe))
        (__shadow-class__% __tmp149468 '((acyclic: . #t)))))
    (define builtin-object?
      (lambda (_%obj149376%_)
        (let ((_%$e149378%_
               (not (let ()
                      (declare (not safe))
                      (##structure? _%obj149376%_)))))
          (if _%$e149378%_
              _%$e149378%_
              (not (let ((__tmp149469
                          (let ()
                            (declare (not safe))
                            (##structure-type _%obj149376%_))))
                     (declare (not safe))
                     (##structure-instance-of? __tmp149469 'class)))))))
    (define builtin-subtyped?
      (lambda (_%obj149374%_)
        (if (let () (declare (not safe)) (##subtyped? _%obj149374%_))
            (builtin-object? _%obj149374%_)
            '#f)))
    (define builtin-structure?
      (lambda (_%obj149372%_)
        (if (let () (declare (not safe)) (##structure? _%obj149372%_))
            (not (let ((__tmp149470
                        (let ()
                          (declare (not safe))
                          (##structure-type _%obj149372%_))))
                   (declare (not safe))
                   (##structure-instance-of? __tmp149470 'class)))
            '#f)))
    (define atom?
      (lambda (_%obj149370%_)
        (if (let () (declare (not safe)) (##special? _%obj149370%_))
            (let ((__tmp149471
                   (let ()
                     (declare (not safe))
                     (##type-cast _%obj149370%_ '0))))
              (declare (not safe))
              (##fx< __tmp149471 '0))
            '#f)))
    (define special-object?
      (lambda (_%obj149368%_)
        (let () (declare (not safe)) (##special? _%obj149368%_))))
    (define unbound-object?
      (lambda (_%obj149366%_) (eq? _%obj149366%_ '#!unbound)))
    (define unbound2-object?
      (lambda (_%obj149364%_) (eq? _%obj149364%_ '#!unbound2)))
    (define unused-object?
      (lambda (_%obj149362%_) (eq? _%obj149362%_ (macro-unused-obj))))
    (define deleted-object?
      (lambda (_%obj149360%_) (eq? _%obj149360%_ (macro-deleted-obj))))
    (define absent-object?
      (lambda (_%obj149358%_) (eq? _%obj149358%_ (macro-absent-obj))))
    (define ddsl-token?
      (lambda (_%obj149350%_)
        (let ((_%$e149352%_ (eq? _%obj149350%_ '#!key)))
          (if _%$e149352%_
              _%$e149352%_
              (let ((_%$e149355%_ (eq? _%obj149350%_ '#!optional)))
                (if _%$e149355%_ _%$e149355%_ (eq? _%obj149350%_ '#!rest)))))))
    (define dssl-key? (lambda (_%obj149348%_) (eq? _%obj149348%_ '#!key)))
    (define dssl-optional?
      (lambda (_%obj149346%_) (eq? _%obj149346%_ '#!optional)))
    (define dssl-rest? (lambda (_%obj149344%_) (eq? _%obj149344%_ '#!rest)))
    (define stflonum?
      (lambda (_%obj149342%_)
        (if (flonum? _%obj149342%_)
            (not (let ()
                   (declare (not safe))
                   (##mem-allocated? _%obj149342%_)))
            '#f)))
    (define haflonum?
      (lambda (_%obj149340%_)
        (if (flonum? _%obj149340%_)
            (let () (declare (not safe)) (##mem-allocated? _%obj149340%_))
            '#f)))
    (define __subtyped-class-sequence
      (let ((_%vec149337%_
             (let () (declare (not safe)) (##make-vector '32 '#f))))
        (vector-set! _%vec149337%_ (macro-subtype-boxvalues) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-string) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-s8vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-u8vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-s16vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-u16vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-s32vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-u32vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-f32vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-s64vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-u64vector) '#t)
        (vector-set! _%vec149337%_ (macro-subtype-f64vector) '#t)
        _%vec149337%_))
    (define sequence?
      (lambda (_%obj149335%_)
        (if (let () (declare (not safe)) (##subtyped? _%obj149335%_))
            (let ((__tmp149472
                   (let () (declare (not safe)) (##subtype _%obj149335%_))))
              (declare (not safe))
              (##vector-ref __subtyped-class-sequence __tmp149472))
            '#f)))
    (define __subtyped-class-hvector
      (let ((_%vec149332%_
             (let () (declare (not safe)) (##make-vector '32 '#f))))
        (vector-set! _%vec149332%_ (macro-subtype-s8vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-u8vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-s16vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-u16vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-s32vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-u32vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-f32vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-s64vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-u64vector) '#t)
        (vector-set! _%vec149332%_ (macro-subtype-f64vector) '#t)
        _%vec149332%_))
    (define hvector?
      (lambda (_%obj149330%_)
        (if (let () (declare (not safe)) (##subtyped? _%obj149330%_))
            (let ((__tmp149473
                   (let () (declare (not safe)) (##subtype _%obj149330%_))))
              (declare (not safe))
              (##vector-ref __subtyped-class-hvector __tmp149473))
            '#f)))
    (define weak?
      (lambda (_%obj149328%_)
        (if (let () (declare (not safe)) (##subtyped? _%obj149328%_))
            (eq? (let () (declare (not safe)) (##subtype _%obj149328%_))
                 (macro-subtype-weak))
            '#f)))
    (define object-port?
      (lambda (_%obj149326%_)
        (let ((__tmp149474
               (let ((__tmp149475 (macro-type-object-port)))
                 (declare (not safe))
                 (##type-id __tmp149475))))
          (declare (not safe))
          (##structure-instance-of? _%obj149326%_ __tmp149474))))
    (define character-port?
      (lambda (_%obj149324%_)
        (let ((__tmp149476
               (let ((__tmp149477 (macro-type-character-port)))
                 (declare (not safe))
                 (##type-id __tmp149477))))
          (declare (not safe))
          (##structure-instance-of? _%obj149324%_ __tmp149476))))
    (define byte-port?
      (lambda (_%obj149322%_)
        (let ((__tmp149478
               (let ((__tmp149479 (macro-type-byte-port)))
                 (declare (not safe))
                 (##type-id __tmp149479))))
          (declare (not safe))
          (##structure-instance-of? _%obj149322%_ __tmp149478))))
    (define device-port?
      (lambda (_%obj149320%_)
        (let ((__tmp149480
               (let ((__tmp149481 (macro-type-device-port)))
                 (declare (not safe))
                 (##type-id __tmp149481))))
          (declare (not safe))
          (##structure-instance-of? _%obj149320%_ __tmp149480))))
    (define vector-port?
      (lambda (_%obj149318%_)
        (let ((__tmp149482
               (let ((__tmp149483 (macro-type-vector-port)))
                 (declare (not safe))
                 (##type-id __tmp149483))))
          (declare (not safe))
          (##structure-instance-of? _%obj149318%_ __tmp149482))))
    (define string-port?
      (lambda (_%obj149316%_)
        (let ((__tmp149484
               (let ((__tmp149485 (macro-type-string-port)))
                 (declare (not safe))
                 (##type-id __tmp149485))))
          (declare (not safe))
          (##structure-instance-of? _%obj149316%_ __tmp149484))))
    (define u8vector-port?
      (lambda (_%obj149314%_)
        (let ((__tmp149486
               (let ((__tmp149487 (macro-type-u8vector-port)))
                 (declare (not safe))
                 (##type-id __tmp149487))))
          (declare (not safe))
          (##structure-instance-of? _%obj149314%_ __tmp149486))))
    (define raw-device-port?
      (lambda (_%obj149312%_)
        (let ((__tmp149488
               (let ((__tmp149489 (macro-type-raw-device-port)))
                 (declare (not safe))
                 (##type-id __tmp149489))))
          (declare (not safe))
          (##structure-instance-of? _%obj149312%_ __tmp149488))))
    (define tcp-server-port?
      (lambda (_%obj149310%_)
        (let ((__tmp149490
               (let ((__tmp149491 (macro-type-tcp-server-port)))
                 (declare (not safe))
                 (##type-id __tmp149491))))
          (declare (not safe))
          (##structure-instance-of? _%obj149310%_ __tmp149490))))
    (define udp-port?
      (lambda (_%obj149308%_)
        (let ((__tmp149492
               (let ((__tmp149493 (macro-type-udp-port)))
                 (declare (not safe))
                 (##type-id __tmp149493))))
          (declare (not safe))
          (##structure-instance-of? _%obj149308%_ __tmp149492))))
    (define directory-port?
      (lambda (_%obj149306%_)
        (let ((__tmp149494
               (let ((__tmp149495 (macro-type-directory-port)))
                 (declare (not safe))
                 (##type-id __tmp149495))))
          (declare (not safe))
          (##structure-instance-of? _%obj149306%_ __tmp149494))))
    (define event-queue-port?
      (lambda (_%obj149304%_)
        (let ((__tmp149496
               (let ((__tmp149497 (macro-type-event-queue-port)))
                 (declare (not safe))
                 (##type-id __tmp149497))))
          (declare (not safe))
          (##structure-instance-of? _%obj149304%_ __tmp149496))))
    (define readenv?
      (lambda (_%obj149302%_)
        (let ((__tmp149498
               (let ((__tmp149499 (macro-type-readenv)))
                 (declare (not safe))
                 (##type-id __tmp149499))))
          (declare (not safe))
          (##structure-instance-of? _%obj149302%_ __tmp149498))))
    (define writeenv?
      (lambda (_%obj149300%_)
        (let ((__tmp149500
               (let ((__tmp149501 (macro-type-writeenv)))
                 (declare (not safe))
                 (##type-id __tmp149501))))
          (declare (not safe))
          (##structure-instance-of? _%obj149300%_ __tmp149500))))
    (define vm?
      (lambda (_%obj149298%_)
        (let ((__tmp149502
               (let ((__tmp149503 (macro-type-vm)))
                 (declare (not safe))
                 (##type-id __tmp149503))))
          (declare (not safe))
          (##structure-instance-of? _%obj149298%_ __tmp149502))))))
