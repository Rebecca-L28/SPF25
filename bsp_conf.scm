;; BSP confidentiality model
;; Henry Harborne
;; Spacecraft transmits an encrypted payload under a long-term symmetric key
;; shared with the groundstation. Tests if CPSA can derive the plaintext.

(defprotocol bsp_conf basic

  ;; spacecraft role: encrypts and sends payload
  (defrole spacecraft
    (vars (sc gs name) (payload text))
    (trace
      ;; spacecraft sends (sc, gs, enc(payload, ltk(sc, gs)))
      (send (cat sc gs (enc payload (ltk sc gs))))))

  ;; groundstation role: receives and decrypts
  (defrole groundstation
    (vars (sc gs name) (payload text))
    (trace
      ;; groundstation receives (sc, gs, enc(payload, ltk(sc, gs)))
      (recv (cat sc gs (enc payload (ltk sc gs))))))

  ;; observer role: adversary that sees ciphertext
  (defrole observer
    (vars (sc gs name) (leak text))
    (trace
      ;; observer receives the encrypted transmission
      (recv (cat sc gs leak))))
)

;; skeleton modeling confidentiality
(defskeleton bsp_conf
  ;; spacecraft name, groundstation name, and payload
  (vars (sc0 gs0 name) (payload0 text))

  ;; spacecraft sends the encrypted payload
  (defstrand spacecraft 1
    (sc sc0) (gs gs0) (payload payload0))

  ;; groundstation receives it
  (defstrand groundstation 1
    (sc sc0) (gs gs0) (payload payload0))

  ;; adversary observes ciphertext
  (defstrand observer 1
    (sc sc0) (gs gs0))

  ;; assume key is secret (adversary doesn’t know ltk)
  (non-orig (ltk sc0 gs0))

  ;; mark payload as freshly created, unique to this run
  (uniq-orig payload0)
)
