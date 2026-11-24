;;; -*- Gerbil -*-
;;; (C) vyzo
;;; Command-line option and command argument parsing
(import (only-in :std/struct/option Some Some-value value->option)
        :std/error
        :std/format
        :std/iter
        :std/hash/misc
        :std/list/list
        :std/string/misc
        :std/list/list-builder)
(export getopt
        (rename: !getopt? getopt?)
        (rename: !top? getopt-object?)
        getopt-error?
        getopt-parse
        getopt-display-help
        getopt-display-help-topic
        option
        flag
        command
        defgetopt-dispatch
        getopt-dispatch
        call-with-getopt-dispatch
        argument
        optional-argument
        rest-arguments
        call-with-getopt
        getopt-parse->function-arguments
        call-with-getopt-parse)

(def current-getopt-parser
  (make-parameter #f))

(deferror-class GetOptError (getopt) getopt-error?
  (lambda (self msg args getopt)
    (Error:::init! self msg where: 'getopt irritants: args)
    (set! (@ self getopt) getopt)))
(def (raise-getopt-error msg . args)
  (raise (GetOptError msg args (current-getopt-parser))))
(def getopt-error-e GetOptError-getopt)

(defstruct !getopt (opts cmds args help))
(defstruct !top (key help))
(defstruct (!command !top) (parser)
  final: #t)
;; A supplied default or optional value is wrapped so it can itself be #f.
(defstruct (!opt !top) (short long parse default))
(defstruct (!option !opt) ())
(defstruct (!flag !opt) ()
  final: #t)
(defstruct (!arg !top) (parse))
(defstruct (!reqarg !arg) ()
  final: #t)
(defstruct (!optarg !arg) (default)
  final: #t)
(defstruct (!rest !arg) ()
  final: #t)

(def (spec-parser id parse value)
  (cond
   ((eq? parse absent-value)
    (if (eq? value absent-value) identity value))
   ((eq? value absent-value) parse)
   (else (error "Illegal specifier; parse: and its alias value: are mutually exclusive" id))))

(def (getopt help: (help #f) . args)
  (let lp ((rest args) (opts []) (cmds []) (args []))
    (match rest
      ([hd . rest]
       (cond
        ((!opt? hd)
         (lp rest (cons hd opts) cmds args))
        ((!command? hd)
         (if (null? args)
           (lp rest opts (cons hd cmds) args)
           (error "Illegal command; already have arguments" hd)))
        ((!reqarg? hd)
         (if (null? cmds)
           (if (or (null? args)
                   (and (not (!optarg? (car args)))
                        (not (!rest? (car args)))))
             (lp rest opts cmds (cons hd args))
             (error "Illegal required argument; already have optional or rest arguments" hd))
           (error "Illegal required argument; already have commands" hd)))
        ((or (!optarg? hd)
             (!rest? hd))
         (if (null? cmds)
           (if (or (null? args)
                   (not (!rest? (car args))))
             (lp rest opts cmds (cons hd args))
             (error "Illegal optional argument; already have rest arguments" hd))
           (error "Illegal optional argument; alreday have commands" hd)))
        (else
         (error "Illegal argument; must be a getopt-object" hd))))
      (else
       (let (opts (reverse opts))
         (check-option-specs! opts)
         (make-!getopt opts (reverse cmds) (reverse args) help))))))

;; Option spellings are unique within each command. Scalar aliases may share
;; one default.
(def (check-option-specs! opts)
  (def names (make-hash-table))
  (def ids (make-hash-table-eq))
  (for-each
   (lambda (opt)
     (with ((!opt id _ short long _ default) opt)
       (def previous (hash-get ids id))
       (def (claim-name! name)
         (when name
           (when (hash-key? names name)
             (raise-contract-violation getopt "unique option name within a command"
                                       name: name first-id: (hash-get names name)
                                       second-id: id))
           (hash-put! names name id)))
       (claim-name! short)
       (claim-name! long)
       (when previous
         (when (and default (!opt-default previous))
           (raise-contract-violation getopt "one default per option id" id: id)))
       (when (or default (not previous))
         (hash-put! ids id opt))))
   opts))

(def (make-flag-spec id (short :? :string) (long :? :string := #f)
           help: (help :? :string := #f)
           parse: (parse absent-value)
           value: (value absent-value)
           default: (default absent-value))
  => !flag
  (make-!flag id help short long
              (spec-parser id parse value)
              (value->option default absent-value)))

;; TODO: remove the flag and option aliases once the compiler handles interleaved
;; positional and keyword arguments to typed procedures. The compiler fix was
;; dropped from PR #1519: https://git.cons.io/mighty-gerbils/gerbil/pulls/1519
;; The aliases keep these calls on the runtime dispatcher.
(def flag make-flag-spec)

;; An option with a value: as the next word (-c 5, --counter 5), attached to
;; the long name after = (--counter=5) or to a two-character short name (-c5).
(def (make-option-spec id (short :? :string) (long :? :string := #f)
             help: (help :? :string := #f)
             parse: (parse absent-value)
             value: (value absent-value)
             default: (default absent-value))
  => !option
  (make-!option id help short long
                (spec-parser id parse value)
                (value->option default absent-value)))

;; Same compiler workaround as flag above.
(def option make-option-spec)

(def (command id help: (help #f) . args)
  (make-!command id help (apply getopt help: help args)))

;; A required positional argument, converted with parse: (alias value:).
(def (argument id
               help: (help #f)
               parse: (parse absent-value)
               value: (value absent-value))
  (make-!reqarg id help (spec-parser id parse value)))

;; An optional positional argument, converted with parse: (alias value:);
;; default: (not converted) when absent.
(def (optional-argument id
                        help: (help #f)
                        parse: (parse absent-value)
                        value: (value absent-value)
                        default: (default #f))
  (make-!optarg id help (spec-parser id parse value)
                default))

;; All remaining positional arguments, each converted with parse: (alias value:).
(def (rest-arguments id
                     help: (help #f)
                     parse: (parse absent-value)
                     value: (value absent-value))
  (make-!rest id help (spec-parser id parse value)))

;; Only leaves have an arrow. Select the table shape during expansion.
(defrules defgetopt-dispatch (=>)
  ((_ name (key => handler) ...)
   (defcommand-table name (key => handler) ...))
  ((_ name (key target ...) ...)
   (defmulti-command-table name (key target ...) ...)))

;; Delay lookup so a handler can be defined after the dispatch table.
(defrules defcommand-table (=>)
  ((_ name (key => handler) ...)
   (def name (delay-atomic (hash-eq (key handler) ...)))))

(defrule (defmulti-command-table name (key target ...) ...)
  (def name (delay-atomic (hash-eq (key (dispatch-target target ...)) ...))))

(defrules dispatch-target (=>)
  ((_ => handler) handler)
  ((_ entry entries ...)
   (let ()
     (defgetopt-dispatch subtable entry entries ...)
     subtable)))

(def (getopt-dispatch (table   : :promise)
                      command
                      (options :~ hash-table?))
  => :t
  ((getopt-command-handler table command) options))

(def (getopt-command-handler (table : :promise) command)
  => :procedure
  (let loop ((path (if (symbol? command) [command] command)) (table table))
    (match path
      ([key . rest]
       (let (entry (hash-get (force table) key))
         (cond
          ((and (null? rest) (procedure? entry)) entry)
          ((and (pair? rest) (promise? entry)) (loop rest entry))
          (else (raise-getopt-error "No handler for command" command)))))
      (else (raise-getopt-error "Expected a nonempty command path" command)))))

(def (getopt-parse gopt args)
  (parse-command-line gopt args #f))

(def (parse-command-line gopt args show-help (finish values))
  (let ((ht (make-hash-table-eq))
        (nested? (ormap (lambda (cmd) (pair? (!getopt-cmds (!command-parser cmd))))
                        (!getopt-cmds gopt))))
    (let parse ((node gopt) (path []) (rest args))
      (parameterize ((current-getopt-parser (cons node path)))
        (with ((!getopt opts cmds args) node)
          (getopt-parse-opts! ht opts rest
            (lambda () (show-help (reverse path)))
            (lambda (rest)
              (cond
               ((null? cmds)
                (getopt-parse-args! ht args rest)
                (cond
                 ((eq? node (!command-parser help-command))
                  (show-help (append (reverse (cdr path)) (hash-ref ht 'command))))
                 ((null? path) (finish ht))
                 (nested? (finish (reverse path) ht))
                 (else (finish (car path) ht))))
               ((null? rest) (raise-getopt-error "Missing command"))
               ((find-command cmds (car rest))
                => (lambda (cmd)
                     (parse (!command-parser cmd) (cons (!top-key cmd) path) (cdr rest))))
               (else (raise-getopt-error "Unknown command" (car rest)))))))))))

(def (find-command (cmds : :list) (name : :string))
  ;; For duplicate command names, the last declaration wins.
  (foldl (lambda (cmd previous)
           (if (string=? name (symbol->string (!top-key cmd))) cmd previous))
         #f cmds))

;; Parse the options at the head of the words in rest, then call K with the remaining words.
;; Option parsing ends at "--" (dropped) or at the first word not starting with "-".
;; A word naming a registered option exactly takes precedence; otherwise
;; --name=value attaches a value after the first =, and -cVALUE attaches a value
;; to the two-character short name -c. Both forms are errors for flags.
;; TODO: short-flag clustering (-bv as -b -v), at least for flags.
;; TODO: opt-in GNU-style permutation, allowing options after positional arguments.
(def (getopt-parse-opts! ht opts rest show-help K)
  (def names (make-hash-table))
  (for-each (lambda (opt)
              (when (!opt-short opt) (hash-put! names (!opt-short opt) opt))
              (when (!opt-long opt) (hash-put! names (!opt-long opt) opt)))
            opts)

  (def (store! opt value)
    (hash-put! ht (!top-key opt) value))

  (def (end rest)
    (for-each
     (lambda (opt)
       (let (id (!top-key opt))
         (unless (hash-key? ht id)
           (cond
            ((!opt-default opt) => (lambda (default) (hash-put! ht id (Some-value default))))))))
     opts)
    (K rest))

  ;; hd is not a registered name: try --name=value or -cVALUE.
  (def (attached-value! hd)
    (let* ((len (string-length hd))
           (long? (and (fx> len 1) (eqv? (string-ref hd 1) #\-)))
           (split (if long? (string-index hd #\=) (and (fx> len 2) 2)))
           (entry (and split (hash-get names (substring hd 0 split)))))
      (cond
       ((not entry)
        (raise-getopt-error "Unknown option" hd))
       ((!flag? entry)
        (raise-getopt-error "Unexpected value for flag" hd))
       (else
        (store! entry ((!opt-parse entry)
                       (substring hd (if long? (fx+ split 1) split) len)))))))

  (let lp ((rest rest))
    (match rest
      ([hd . rest*]
       (cond
        ((string-empty? hd)
         (lp rest*))
        ((eq? (string-ref hd 0) #\-)
         (cond
          ((equal? "--" hd)             ; end of options
           (end rest*))
          ((hash-get names hd)
           => (lambda (opt)
                (cond
                 ((eq? opt help-flag) (show-help))
                 ((!flag? opt)
                  (store! opt ((!opt-parse opt) #t))
                  (lp rest*))
                 (else
                  (match rest*
                    ([val . rest*]
                     (store! opt ((!opt-parse opt) val))
                     (lp rest*))
                    (else
                     (raise-getopt-error "Missing value for option" hd)))))))
          (else
           (attached-value! hd)
           (lp rest*))))
        (else                           ; doesn't look like an option
         (end rest))))
      (else                             ; we run out of arguments
       (end rest)))))

(def (getopt-parse-args! ht args rest)
  (let lp ((args args) (rest rest))
    (match args
      ([arg . args]
       (match arg
         ((!reqarg key _ value-e)
          (match rest
            ([val . rest]
             (hash-put! ht key (value-e val))
             (lp args rest))
            (else
             (raise-getopt-error "Missing argument" key))))
         ((!optarg key _ value-e default)
          (match rest
            ([val . rest]
             (hash-put! ht key (value-e val))
             (lp args rest))
            (else
             (hash-put! ht key default)
             (lp args rest))))
         ((!rest key _ value-e)
          (hash-put! ht key (map value-e rest))
          ht)))
      (else
       (unless (null? rest)
         (raise-getopt-error "Unexpected arguments" rest))
       ht))))

;; The ids of the positional arguments of gopt, in order, and the id of its rest
;; arguments or #f. Each id appears once, at its first declaration, so that ids
;; shared by several specs do not yield duplicate positional parameters.
(def (getopt->positional-names gopt)
  (def rest-name #f)
  (def seen (make-hash-table-eq))
  (def names (with-list-builder (c)
               (for-each (lambda (arg)
                           (let (key (!top-key arg))
                             (unless (hash-key? seen key)
                               (hash-put! seen key #t)
                               (if (!rest? arg)
                                 (set! rest-name key)
                                 (c key)))))
                         (!getopt-args gopt))))
  (values names rest-name))

(def (getopt-display-help obj program (port (current-output-port)))
  (cond
   ((!getopt? obj)
    (display-help-getopt obj program port))
   ((!command? obj)
    (display-help-getopt (!command-parser obj) (command-program (!top-key obj) program) port))
   ((getopt-error? obj)
    (parameterize ((current-output-port port))
      (displayln "Error: " (error-message obj))
      (unless (null? (error-irritants obj))
        (display "Irritants:")
        (for-each (lambda(x) (display* " " x))
                  (error-irritants obj))
        (newline))
      (newline))
    (when (getopt-error-e obj)
      (with ([node . path] (getopt-error-e obj))
        (display-help-getopt node (foldl command-program program (reverse path)) port))))
   (else
    (error "Unexpected object; expected a getopt, getopt-error, or command" obj))))

(def (command-program (key : :symbol) (program : :string))
  => :string
  (string-append program " " (symbol->string key)))

(def (getopt-display-help-topic gopt topic program (port (current-output-port)))
  (let loop ((node gopt) (program program)
             (path (cond ((symbol? topic) [topic]) ((list? topic) topic) (else []))))
    (cond
     ((and (pair? path) (find-command (!getopt-cmds node) (symbol->string (car path))))
      => (lambda (cmd)
           (loop (!command-parser cmd) (command-program (!top-key cmd) program) (cdr path))))
     (else (display-help-getopt node program port)))))

(def (display-help-getopt obj program port)
  (parameterize ((current-output-port port))
    (with ((!getopt opts cmds args help) obj)
      (when help
        (displayln program ": " help)
        (newline))
      (if (null? cmds)
        (begin
          (display* "Usage: " program (if (null? opts) "" " [option ...]"))
          (display-args args port)
          (unless (null? opts)
            (newline)
            (displayln "Options:")
            (display-option-help opts port))
          (unless (null? args)
            (newline)
            (displayln "Arguments:")
            (display-arg-help args port)))
        (begin
          (displayln "Usage: " program (if (null? opts) "" " [option ...]")
                     " <command> command-arg ...")
          (unless (null? opts)
            (newline)
            (displayln "Options:")
            (display-option-help opts port))
          (newline)
          (displayln "Commands:")
          (for-each (match <>
                      ((!command key help)
                       (displayln " " key " " (tabs key) " " (or help "?"))))
                    cmds))))))

(def (display-args args port)
  (parameterize ((current-output-port port))
    (for-each (match <>
                ((!reqarg key)
                 (display* " <" key ">"))
                ((!optarg key)
                 (display* " [<" key ">]"))
                ((!rest key)
                 (display* " <" key "> ...")))
              args)
    (newline)))

(def (display-option-help opts port)
  (parameterize ((current-output-port port))
    (for-each
     (lambda (opt)
       (with ((!opt key help short long) opt)
         (display "  ")
         (when short (display short))
         (when (and short long) (display " "))
         (when long (display long))
         (when (!option? opt) (display* " <" key ">"))
         (newline)
         (display* "    " (or help "?"))
         (when (!opt-default opt) (display* " [default: " (Some-value (!opt-default opt)) "]"))
         (newline)))
     opts)))

(def (display-arg-help args port)
  (parameterize ((current-output-port port))
    (for-each (match <>
                ((!reqarg key help)
                 (displayln " " key " " (tabs key) " " (or help "?")))
                ((!optarg key help _ default)
                 (displayln " " key " " (tabs key) " " (or help "?")
                            " [default: " default "]"))
                ((!rest key help)
                 (displayln " " key " " (tabs key) " " (or help "?"))))
              args)))

(def (tabs . strs)
  (def tablen 31)
  (def (string-e str)
    (if (symbol? str)
      (symbol->string str)
      str))

  (let* (len (foldl + 0 (map string-length (map string-e strs))))
    (if (fx< len tablen)
      (make-string (fx- tablen len) #\space)
      "")))

(def help-flag (flag 'help "-h" "--help" help: "display help"))
(def help-command
  (command 'help help: "display help for a command path"
    (rest-arguments 'command value: string->symbol)))

;; Construct the high-level parser's grammar without mutating reusable commands.
(def (with-automatic-help (parser : !getopt))
  => !getopt
  (with ((!getopt opts cmds args help) parser)
    (let (opts (append opts [help-flag]))
      (check-option-specs! opts)
      (make-!getopt
        opts
        (if (null? cmds) []
          (append (map (lambda (cmd)
                         (make-!command (!top-key cmd) (!top-help cmd)
                                        (with-automatic-help (!command-parser cmd))))
                       cmds)
                  [help-command]))
        args help))))

(def (call-with-getopt proc args
                       program: program
                       help: (help #f)
                       exit-on-error: (exit? (exit-on-error?))
                       . gopts)
  (run-getopt proc values args program help exit? gopts))

;; Finish parsing and resolve any handler under the leaf's error context.
;; Invoke application code after leaving the parse error handler.
(def (run-getopt proc finish args program help exit? gopts)
  (let (gopt (with-automatic-help (apply getopt help: help gopts)))
    (let/cc done
      (def (show-help path)
        (getopt-display-help-topic gopt path program)
        (done (void)))
      (call-with-values
       (lambda ()
         (try
          (parse-command-line gopt args show-help finish)
          (catch (e)
            (cond
             ((not exit?) (raise e))
             ((getopt-error? e)
              (getopt-display-help e program (current-error-port))
              (exit 1))
             (else (exit-with-error e))))))
       proc))))

;; Parse errors and help are handled before calling a leaf handler.
(def (call-with-getopt-dispatch (table : :promise)
                                (args  : :list)
                                program: program
                                help: (help #f)
                                exit-on-error: (exit? (exit-on-error?))
                                . specs)
  (def* resolve
    ((_) (raise-getopt-error "Missing command"))
    ((command options) (values (getopt-command-handler table command) options)))
  (run-getopt (lambda (handler options) (handler options))
              resolve args program help exit? specs))

(def (getopt-parse->positional-arguments! gopt h)
  (defvalues (names rest-name) (getopt->positional-names gopt))
  (def (extract n) (begin0 (hash-get h n) (hash-remove! h n)))
  (def positional (map extract names))
  (def rest (when/list rest-name (extract rest-name)))
  (append positional rest))

(def (getopt-parse->function-arguments gopt h)
  (def positionals (getopt-parse->positional-arguments! gopt h))
  (append positionals
          (foldr (lambda (kv l) (cons* (make-keyword (car kv)) (cdr kv) l)) '()
                 (hash->list/sort h as-string<?))))

(def (call-with-getopt-parse gopt hash fun)
  (apply fun (getopt-parse->function-arguments gopt hash)))
