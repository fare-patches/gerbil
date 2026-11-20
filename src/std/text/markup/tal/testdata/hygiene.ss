;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Templates whose parameters and neighbours have the names of the TAL
;;; runtime's procedures and temporaries and of core forms (not quote: the
;;; templates' own expressions use it). Loaded from source and compiled
;;; with gxc -O by :std/text/markup/tal-test; both must render the same.
(import :std/text/markup/tal)
(export hygiene-results)

;;; definitions named like TAL internals, legacy and current
(def (integer->roman n) "MINE")
(def (push-toplevel x) "MINE2")
(def (tal-emit-text! . args) "MINE3")
(def (repeat-number r) "MINE4")

(define-TAL (helpers tal-render-template tal-scope tal-on-error-scope tal-user
                     tal-emit-bytes! tal-emit-text! tal-emit-as-is! tal-emit-raw!
                     tal-emit-raw-text! tal-emit-attribute! make-TALSwitch
                     current-tal-switch tal-case? tal-case-else? make-tal-repeat
                     tal-repeat-next! tal-repeat-item repeat-index repeat-number
                     html-escape tal:write %r %body p t u8v tal-raise? tal:loop
                     render mark depth using let if begin void eq? with* lambda)
  "<div tal:switch=\"'a\"><p tal:case=\"'a\" tal:define=\"(x tal-scope)\" tal:attributes=\"(title tal-user)\"><i tal:repeat=\"(i (list p t))\" tal:content=\"(list i (repeat/i.number))\">-</i><s tal:content=\"(string-append x render mark depth using)\" tal:on-error=\"'E\">-</s><u tal:content=\"%r\">-</u><script tal:content=\"u8v\"></script><em tal:replace=\"as-is: let\">-</em><q tal:content=\"raw: if\">-</q><a tal:content=\"(string-append html-escape tal:write)\">-</a><b tal:content=\"'|<y>|\">-</b></p></div>")

(define-TAL (user-definitions)
  "<b tal:content=\"(list (integer->roman 4) (push-toplevel 1) (tal-emit-text! 1) (repeat-number 0))\">x</b>")

(define-TAL (err-outside-on-error err)
  "<b tal:content=\"err\">x</b>")

(def (render thunk)
  (utf8->string
   (call-with-output-u8vector #u8()
     (lambda (port)
       (parameterize ((current-tal-output-port port))
         (thunk))))))

;;; Each template's output.
(def (hygiene-results)
  [(render
    (lambda ()
      (helpers "tal-render-template" "tal-scope" "tal-on-error-scope" "tal-user"
               "tal-emit-bytes!" "tal-emit-text!" "tal-emit-as-is!" "tal-emit-raw!"
               "tal-emit-raw-text!" "tal-emit-attribute!" "make-TALSwitch"
               "current-tal-switch" "tal-case?" "tal-case-else?" "make-tal-repeat"
               "tal-repeat-next!" "tal-repeat-item" "repeat-index" "repeat-number"
               "html-escape" "tal:write" "%r" "%body" "p" "t" "u8v" "tal-raise?" "tal:loop"
               "render" "mark" "depth" "using" "let" "if" "begin" "void" "eq?" "with*" "lambda")))
   (render user-definitions)
   (render (lambda () (err-outside-on-error "E")))])
