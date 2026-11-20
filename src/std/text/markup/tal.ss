;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; TAL: the Template Attribute Language, over the typed HTML modules.
;;;
;;; (define-TAL (name arg ...) template) defines a procedure that writes the
;;; HTML template, with its tal: statements evaluated, to
;;; current-tal-output-port. template is a string literal (string: may
;;; precede it) or file: and a path relative to the source file. The
;;; template is read and compiled when the form expands: syntax errors in it
;;; are reported as path:line:column. Expressions in the template see the
;;; bindings of the defining module, and nothing else.
(import ./tal/runtime
        (for-syntax ./tal/reader
                    ./tal/compiler))
(export define-TAL
        current-tal-output-port
        current-tal:on-error
        tal:write)

(begin-syntax
  ;; The template text of a define-TAL form, and where it comes from:
  ;; (values text path line column), line and column (0-based) where the
  ;; text starts in path, or path #f.
  (def (template-source stx kind spec)
    (let* ((locat (stx-source stx))
           (container (and locat (##locat-container locat)))
           (source-path (and container (##container->path container))))
      (if (eq? kind file:)
        (let (path (path-expand (stx-e spec)
                                (if source-path (path-directory source-path) (current-directory))))
          (values (call-with-input-file [path: path char-encoding: 'UTF-8]
                    (lambda (port) (or (read-line port #f) "")))
                  path 0 0))
        (let* ((locat (stx-source spec))
               (position (and locat (##locat-start-position locat))))
          (values (stx-e spec)
                  source-path
                  (if position (##filepos-line position) 0)
                  ;; past the opening quote
                  (if position (fx+ (##filepos-col position) 1) 0))))))

  ;; The syntax of datum, a form of the compiler: symbols starting with %
  ;; are temporaries, each a fresh identifier; other symbols refer to the
  ;; bindings of this module.
  (def (template-syntax datum)
    (let (temporaries (make-hash-table-eq))
      (let recur ((e datum))
        (cond
         ((pair? e) (cons (recur (car e)) (recur (cdr e))))
         ((and (symbol? e) (eq? (string-ref (symbol->string e) 0) #\%))
          (or (hash-get temporaries e)
              (let (id (genident e))
                (hash-put! temporaries e id)
                id)))
         ((symbol? e) (datum->syntax (quote-syntax tal-render-template) e))
         (else e)))))

  ;; The define-TAL definition of name with parameters args, rendering
  ;; text (from path at line, column).
  (def (expand-template stx name args text path line column)
    (def locate (tal-offset-locator text))
    (def (place offset)
      (let* ((line+column (locate offset))
             (template-line (car line+column))
             (template-column (cadr line+column)))
        (values (fx+ line (fx- template-line 1))
                (fx- (if (fx= template-line 1) (fx+ column template-column) template-column) 1))))
    (def (fail offset message)
      (let-values (((line column) (place offset)))
        (raise-syntax-error
         #f
         (string-append (or path "<template>") ":" (number->string (fx+ line 1))
                        ":" (number->string (fx+ column 1)) ": " message)
         stx)))
    (def (user datum offset)
      (datum->syntax name datum
                     (and path
                          (let-values (((line column) (place offset)))
                            (##make-locat (##path->container path)
                                          (##make-filepos line column 0)
                                          #f)))))
    (let* ((template (read-tal-template text fail))
           (body (compile-tal-template template fail user))
           (render (template-syntax ['lambda '(%r) '(void) body ...])))
      (with-syntax ((name name)
                    ((arg ...) args)
                    (render render))
        #'(def (name arg ...)
            (tal-render-template render))))))

(defsyntax (define-TAL stx)
  (syntax-case stx ()
    ((_ (name arg ...) template)
     (stx-string? #'template)
     (let-values (((text path line column) (template-source stx string: #'template)))
       (expand-template stx #'name #'(arg ...) text path line column)))
    ((_ (name arg ...) kind template)
     (and (memq (stx-e #'kind) [string: file:]) (stx-string? #'template))
     (let-values (((text path line column) (template-source stx (stx-e #'kind) #'template)))
       (expand-template stx #'name #'(arg ...) text path line column)))))
