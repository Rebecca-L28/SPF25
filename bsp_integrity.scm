;; CPSA model for Bundle Security Protocol integrity using abstract PIB tags
;; Rebecca Lee

(defprotocol bsp_integrity basic

  ;; bundle spacaecraft role which sends the payload with the integrity tag
  (defrole spacecraft
    ;; declare the variables: sc is name of spacecraft, payload is the
    ;; text(message exchanged), tag is the tag
    (vars (sc name) (payload text) (tag text))
    ;; trace is what the role does, sends bundle
    (trace
      (send (cat sc payload tag))))

  ;; bundle groundstation role which receives the payload and tag
  (defrole groundstation
    ;; declare the variables: sc is name of spacecraft, payload is the
    ;; text(message exchanged), tag is the tag
    (vars (sc name) (payload text) (tag text))
    ;; trace is what the role does, receives bundle
    (trace
      (recv (cat sc payload tag))))

  ;; the observersc role (the adversary) which attempts to receive an altered
  ;; payload  with the same tag
  (defrole observersc
    ;; declare the variables: sc is name of spacecraft, x is the
    ;; text(message exchanged), tag is the tag
    (vars (sc name) (x text) (tag text))
    ;; trace is what the role does, receives the tampered bundle
    (trace
      (recv (cat sc x tag))))
)

;; defining the skeleton which has a valid spacecraft(source) and groundstation(destination) as well as
;; an attempted tampering by the observer
(defskeleton bsp_integrity
  ;; declare the variables: sc0 is name of spacecraft, payload0 is the
  ;; text(message exchanged), tag0 is the tag
  (vars (sc0 name) (payload0 text) (tag0 text))

  ;; valid spacecraft sends the (sc0, payload0, tag0) bundle
  (defstrand spacecraft 1
    (sc sc0) (payload payload0) (tag tag0))

  ;; valid groundstation recieves the (sc0, payload0, tag0) bundle
  (defstrand groundstation 1
    (sc sc0) (payload payload0) (tag tag0))

  ;; the observer attempts to receive the (sc0, x ≠ payload0, tag0) bundle
  ;; this tests if CPSA can realize a tampered message with a valid tag
  (defstrand observersc 1
    (sc sc0) (x payload0) (tag tag0))
)
