;; SDLS confidentiality model
;; Henry Harborne
;; Ground station encrypts a freshly generated payload using the LTK.
;; Listener tries to learn the raw payload. If confidentiality holds,
;; CPSA should produce no shapes.

(defprotocol sdls_conf basic

  ;; ground creates fresh payload & encrypts it under pairwise LTK
  (defrole ground
    (vars (sc gs name) (payload text))
    (trace
      (send (cat sc gs (enc payload (ltk sc gs))))))

)

;; confidentiality skeleton
(defskeleton sdls_conf
  (vars (sc0 gs0 name) (payload0 text))

  ;; ground creates & transmits the encrypted payload
  (defstrand ground 1
    (sc sc0) (gs gs0) (payload payload0))

  ;; adversary tries to learn the plaintext payload
  (deflistener payload0)

  ;; key is secret, intruder cannot derive payload from ciphertext
  (non-orig (ltk sc0 gs0))

  ;; payload is fresh, so listener should not know it
  (uniq-orig payload0)
)

