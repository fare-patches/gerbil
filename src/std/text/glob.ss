;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; Whole-string matching with * and ? wildcards.
(export glob-match?)

;; Whether the whole of str matches the glob pattern.
(def (glob-match? (pattern : :string)
                  (str     : :string))
  => :boolean
  (let ((m (string-length pattern)) (n (string-length str)))
    ;; Retry only the most recent star, consuming one more input character.
    (let loop ((p 0) (i 0) (after-star #f) (retry 0))
      (cond
       ((and (fx< p m) (char=? (string-ref pattern p) #\*))
        (loop (fx1+ p) i (fx1+ p) i))
       ((fx= i n) (fx= p m))
       ((and (fx< p m)
             (let (c (string-ref pattern p))
               (or (char=? c #\?) (char=? c (string-ref str i)))))
        (loop (fx1+ p) (fx1+ i) after-star retry))
       (after-star (loop after-star (fx1+ retry) after-star (fx1+ retry)))
       (else #f)))))
