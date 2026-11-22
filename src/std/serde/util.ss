;;; -*- Gerbil -*-
;;; © vyzo
;;; serde utilities
(import :std/error)
(export #t)

;; class loader
;; a builtin class (no namespace) is written by its type id, e.g. procedure,
;; which names no global; it is then bound as <id>::t, e.g. procedure::t.
;; Otherwise the part before the # names the module, which is loaded only when
;; the global is not already bound: modules loaded from source (e.g. by the
;; expander) are not known to the runtime loader.
(def (load-class (name : :string))
  => class
  (def (reference-it (name : :string))
    (try (global-var-value (weak-string->symbol name))
	 (catch (e)
	   (runtime-contract-violation! load-class (global-ref name) e))))

  ;; get namespace to find the appropriate module; if empty, it is builtin
  (let (klass
	(cond
	 ((string-index name #\#)
	  => (lambda (idx)
	       ;; don't intern name: an uninterned name has no global yet
	       (let (klass (cond ((##find-interned-symbol name) => global-var-value)
				 (else #!unbound)))
		 (if (eq? klass #!unbound)
		   (begin
		     (load-module (substring name 0 idx))
		     (reference-it name))
		   klass))))
	 (else
	  (let (klass (reference-it name))
	    (if (class-type? klass)
	      klass
	      (reference-it (string-append name "::t")))))))
    (when (eq? klass #!unbound)
      (raise-contract-violation load-class class-type-descriptor? name: name))
    (: klass class)))

;; procedure loader: name is the global name of the procedure, as returned by
;; ##procedure-name, e.g. std/log/compress#compress-gzip; the part before the #
;; names the module, which is loaded only when the global is not already bound
;; (modules loaded from source are not known to the runtime loader);
;; if there is no #, the procedure is builtin.
;; TODO: a missing module raises the loader's error, not a ContractViolation;
;;   same in load-class. Decide whether to convert it.
(def (load-procedure (name : :symbol))
  => :procedure
  (let (proc
        (let ((proc (global-var-value name))
              (str (symbol->string name)))
          (cond
           ((not (eq? proc #!unbound)) proc)
           ((string-index str #\#)
            => (lambda (idx)
                 (load-module (substring str 0 idx))
                 (global-var-value name)))
           (else proc))))
    (if (procedure? proc)
      proc
      (raise-contract-violation load-procedure procedure? name: name value: proc))))

;; the value of the global variable named by a symbol, #!unbound if there is none;
;; ##global-var-ref crashes on an (interned) symbol that has no global variable.
(def (global-var-value (name : :symbol))
  (if (##global-var? name)
    (##global-var-ref name)
    #!unbound))

;; the global name of a procedure, if it has one and that global denotes it,
;; i.e. it can be read back with load-procedure; #f otherwise.
(def (procedure-global-name (proc : :procedure))
  (let (name (##procedure-name proc))
    (and (symbol? name)
         (eq? (global-var-value name) proc)
         name)))

;; a weak variant of symbol->string that does not inject
;; new entries to the symbol table
(def (weak-string->symbol (str : :string))
  => :symbol
  (cond
   ((##find-interned-symbol str))
   (else
    (runtime-contract-violation! "no interned symbol for string"
                                 (interned? str)
                                 str))))

(def (weak-string->keyword (str : :string))
  => :keyword
  (cond
   ((##find-interned-keyword str))
   (else
    (runtime-contract-violation! "no interned keyword for string"
                                 (interned? str)
                                 str))))
