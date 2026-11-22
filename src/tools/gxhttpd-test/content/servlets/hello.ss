(import :std/net/http/server
        :std/format)
(export handler-init! request-handler)

(def state "not initialized")

(def (handler-init! cfg)
  (set! state 'initialized))

;; the server calls request-handler once, after handler-init!, to get the RequestHandler
(def (request-handler)
  (new-closure-handler
   (lambda (req res)
     (ResponseHandler-write! res OK '(("Content-Type" . "text/plain"))
                             (string->utf8 (format "hello! I am a servlet and my state is %a\n" state))))))
