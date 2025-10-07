;; CPSA model for SDLS confidentiality
;; Henry Harborne

;; defines protocol called sdls_conf using basic algebra
(defprotocol sdls_conf basic

  ;; defines groundstation role (sender)
  (defrole groundstation
    ;; declare the variables
    ;; a is groundstation, b is spacecraft, message is plaintext data, seq is sequence number
    (vars (a b name) (message text) (seq text))
    ;; trace is what this role actually does
    ;; sends (a, seq, enc(message, ltk(a, b)))
    (trace
      (send (cat a seq (enc message (ltk a b))))))

  ;; defines spacecraft role (receiver)
  (defrole spacecraft
    ;; declare the variables
    ;; a is groundstation, b is spacecraft, message is plaintext data, seq is sequence number
    (vars (a b name) (message text) (seq text))
    ;; trace is what this role actually does
    ;; receives (a, seq, enc(message, ltk(a, b)))
    (trace
      (recv (cat a seq (enc message (ltk a b))))))

  ;; defines listener role (adversary)
  (defrole listener
    ;; declare the variables
    ;; a is groundstation, x is plaintext data adversary tries to learn
    (vars (a name) (x text))
    ;; trace is what this role actually does
    ;; receives (a, x)
    (trace
      (recv (cat a x))))
)

;; define the skeleton
(defskeleton sdls_conf
  ;; declare variables
  ;; a0 is groundstation, b0 is spacecraft, msg0 is message, seq0 is sequence number
  (vars (a0 b0 name) (msg0 text) (seq0 text))

  ;; this strand sends (a0, seq0, enc(msg0, ltk(a0, b0)))
  (defstrand groundstation 1
    (a a0) (b b0) (message msg0) (seq seq0))

  ;; this strand receives (a0, seq0, enc(msg0, ltk(a0, b0)))
  (defstrand spacecraft 1
    (a a0) (b b0) (message msg0) (seq seq0))

  ;; listener attempts to learn plaintext msg0
  (defstrand listener 1
    (a a0) (x msg0))

  ;; long-term key between a0 and b0 is uncompromised
  (non-orig (ltk a0 b0))
)
