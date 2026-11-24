;; -*- Gerbil -*-
;;;; Support for building a single multicall binary.

(export #t)

(import
  :std/cli/getopt
  :std/cli/print-exit
  :std/cli/shell
  :std/format
  :std/hash/misc
  :std/iter
  :std/list/list
  :std/string/misc)

(def current-program (make-parameter [(car (command-line))]))
(def entry-points (make-hash-table))

(def (current-program-string (program (current-program)))
  (string-join (reverse (flatten program)) " "))

(defstruct entry-point (name function help getopt) transparent: #t)

(def (entry-points-getopt-spec (h entry-points))
  (for/collect (([name . e] (hash->list/sort h as-string<?)))
    (apply command name help: (entry-point-help e)
           (->getopt-spec (entry-point-getopt e)))))

;; TODO: also allow a preprocess: function to further process the result of getopt (if specified)
;; or the raw arguments (if no getopt specified).
(def (register-entry-point function
                           id: (id #f) name: (name #f) help: (help #f)
                           getopt: (getopt #f))
  (let (name (make-symbol (or name (string-filter easy-shell-character? (as-string id)))))
    (hash-put! entry-points name (make-entry-point name function help getopt))))

(defrule (define-entry-point (id . formals) (options ...) body ...)
  (begin (def (id . formals) body ...)
         (register-entry-point id id: 'id options ...)))

;; Name of the entry point to call when there are no arguments (with no arguments),
;; and, with fallback: #t, for an unrecognized first argument (passing all arguments).
;; The stock default diagnoses unknown commands and displays general help.
(defmutable multicall-default 'help : :symbol)

(defmutable multicall-fallback? #f : :boolean)

(def (set-default-entry-point! (name : :symbol) fallback: (fallback? : :boolean := #f))
  (multicall-default-set! name)
  (multicall-fallback?-set! fallback?))

(def (raise-unknown-command command (program (current-program-string)))
  (raise (string-append program ": Unknown command " (as-string command) ".\n")))

;; Raises "Unknown command" when command isn't a registered entry point.
(define-entry-point (help . topics)
  (help: "Print help about available commands"
   getopt: [(rest-arguments 'topics help: "subcommand path for which to display help")])
  ;; Dispatch pushes "help" onto the path. A direct call at the root has no parent prefix.
  (when (and (pair? topics) (not (hash-key? entry-points (make-symbol (car topics)))))
    (raise-unknown-command (car topics) (current-program-string (cdr (current-program)))))
  (display-build-manifest (build-manifest/head))
  (newline)
  (def gopt (apply getopt (entry-points-getopt-spec)))
  (def program (current-program-string (cdr (current-program))))
  (getopt-display-help-topic gopt (map make-symbol topics) program))

;; TODO: also handle getopt specifications?
(define-entry-point (meta)
  (help: "Print meta-information for completion purposes"
   getopt: [])
  (displayln (string-join (list-sort string<? (map as-string (hash-keys entry-points))) " ")))

;; TODO: add a flag for shortening the layer names?
(define-entry-point (version all?: (all? #f) layer: (layer #f))
  (help: "Print software version"
   getopt: [(flag 'all? "-a" "--all" help: "also show versions of previous layers")
            (option 'layer "-l" "--layer" help: "show versions for specified layer")])
  (display-build-manifest (cond (all? (build-manifest))
                                (layer (build-manifest/layer layer))
                                (else (build-manifest/head))))
  (newline))

;; Call the entry point named by command (a string or symbol) with args,
;; pushing its name, as a string, on current-program; raise if there is none.
(def (call-entry-point/internal command args)
  (match (hash-get entry-points (make-symbol command))
    (#f (raise-unknown-command command))
    ((entry-point name fun _help getopt)
     (parameterize ((current-program (cons (symbol->string name) (current-program))))
       (call-with-processed-command-line getopt args fun)))))

;; Dispatch the command-line args to an entry point and return its result:
;; no args calls multicall-default with no args; a first arg naming a registered
;; entry point calls it with the rest. Applications opt into forwarding unknown commands.
;; An unregistered multicall-default raises "Unknown command".
(def (dispatch-entry-point . args)
  (match args
    ([] (call-entry-point/internal multicall-default []))
    ([command . rest]
     (cond
      ((hash-key? entry-points (make-symbol command))
       (call-entry-point/internal command rest))
      ((eq? multicall-default 'help)
       (display (current-program-string) (current-error-port))
       (display ": " (current-error-port))
       (write command (current-error-port))
       (display " is not a recognized subcommand.\n" (current-error-port))
       (call-entry-point/internal 'help [])
       (values))
      (multicall-fallback? (call-entry-point/internal multicall-default args))
      (else (raise-unknown-command command))))))

;; Dispatch as dispatch-entry-point, then print the result and exit accordingly
;; (see begin-print-exit in :std/cli/print-exit).
(def (call-entry-point . args)
  (begin-print-exit (apply dispatch-entry-point args)))

(defrules define-multicall-main ()
  ((_ ctx) (with-id ((main ctx "main"))
             (def main call-entry-point)))
  ((d) (d d)))

;; Call function with the arguments of command-line as processed by processor:
;; a getopt parser, or a getopt: spec for ->getopt-spec, except that #f passes
;; command-line through unparsed, options included.
(def (call-with-processed-command-line processor command-line function)
  (cond
   ((getopt? processor)
    (call-with-getopt-parse processor (getopt-parse processor command-line) function))
   ((not processor)
    (apply function command-line))
   (else
    (call-with-processed-command-line (apply getopt (->getopt-spec processor))
                                      command-line function))))

;; For help, #f describes the raw arguments as one rest argument.
;; The list of getopt specifiers for the getopt: spec of an entry point: a list,
;; flattened; a getopt parser without commands, its specifiers; a natural n, the
;; positional arguments arg1 ... argn; #f, rest arguments named rest.
(def (->getopt-spec spec)
  (cond
   ((list? spec) (flatten spec))
   ((getopt? spec) (getopt->specifiers spec))
   ((and (fixnum? spec) (fx>= spec 0))
    (for/collect ((i (in-range 1 (1+ spec)))) (argument (make-symbol "arg" i))))
   ((not spec) [(rest-arguments 'rest)])
   (else (error "Bad getopt spec: expected a list, a getopt parser, a natural or #f" spec))))
