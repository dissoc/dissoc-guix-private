;;; Copyright © 2024 Justin Bishop <mail@dissoc.me>

(define-module (dissoc private packages tablet)
  #:use-module (dissoc gnu packages tablet)
  #:use-module (dissoc private packages linux))

(define-public digimend-module-linux (make-digimend linux-bpf-sched-ext))
