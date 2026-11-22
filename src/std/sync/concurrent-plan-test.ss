;;; -*- Gerbil -*-
;;; © Gerbil contributors
;;; :std/sync/concurrent-plan test

(import ./concurrent-plan
        :std/struct/pqueue
        :std/test
        :std/error)

;; A flat priority is enough for these tests: the job items are plain symbols,
;; so there is no meaningful numeric priority to derive from them.
(def prio (lambda (x) 1))

(def (plan-pq)
  (make-PQueue prio))

(def (plan-push! q item)
  (pqueue-push! q item))

(def (plan-run! fg bg)
  (perform-plan/threads fg bg
    perform: (lambda (item) item)
    on-success: (lambda (item result) result)
    on-failure: (lambda (item reason) (raise reason))
    deterministic-order: #f
    announce: (lambda (item) item)))

(def perform-plan-test
  (test-suite "test :std/sync/concurrent-plan"
    (test-case "foreground semantics: a plain fg/bg plan performs every job"
      (def fg (plan-pq))
      (def bg (plan-pq))
      (def result [])
      (plan-push! fg 'f1)
      (plan-push! bg 'b1)
      (perform-plan/threads
       fg bg
       perform: (lambda (item) (set! result (cons item result)) item)
       on-success: (lambda (item result) result)
       on-failure: (lambda (item reason) (raise reason))
       deterministic-order: #f
       announce: (lambda (item) item))
      (check (equal? (list-sort string<? result) (list 'b1 'f1)) => #t)
      (check (zero? (pqueue-size fg)) => #t)
      (check (zero? (pqueue-size bg)) => #t))
    (test-case "bg worker notification does not consume the caller's mailbox"
      ;; Regression: with background workers the scheduler must not call
      ;; thread-receive on the caller's mailbox. We arm a sentinel on the caller
      ;; (an ordinary application message already waiting there), run one
      ;; background job, and then demand the sentinel is still receivable.
      (def bg (plan-pq))
      (plan-push! bg 'b1)
      ;; Arm a sentinel addressed to the foreground (caller) thread.
      (thread-send (current-thread) 'caller-sentinel)
      (plan-run! (plan-pq) bg)
      ;; The caller's own message must still be in its mailbox, untouched.
      (check (thread-receive 0 'empty) => 'caller-sentinel)
      (check (zero? (pqueue-size bg)) => #t))
    (test-case "a two-element list in the mailbox is not mistaken for a completion"
      ;; Regression: before the fix, an unrelated 2-element list on the caller's
      ;; mailbox was matched as a worker completion and decremented the worker
      ;; count. It must survive untouched on the caller's mailbox.
      (def bg (plan-pq))
      (plan-push! bg 'b1)
      (thread-send (current-thread) (list 1 2))
      (plan-run! (plan-pq) bg)
      (check (thread-receive 0 'empty) => (list 1 2)))))
