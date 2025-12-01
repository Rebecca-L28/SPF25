;; CPSA model for Bundle Security Protocol integrity property
;; Creates a BIB (Bundle Integrity Block)
;; Uses a secret key with a hash function that will test integrity and authentication
;; Rebecca Lee

;; define the protocol called bsp_integrity and use basic algebra
(defprotocol bsp_integrity basic

  ;; spacecraft role that sends the payload with the hash function and secret key
  (defrole spacecraft
    ;; declare the variables
    ;; sc is spacecraft name, gs is groundstation name, payload is the payload
    ;; groundstation name is included so the ltk function can be used
    ;; it will create a unique key for the spacecraft and groundstation
    (vars (sc gs name) (payload text))
    ;; trace is what the role does, sends the payload with the hash and secret key
    (trace
      (send (cat sc payload (hash sc payload (ltk sc gs))))
      )
    )

  ;; groundstation role that receives the payload
  (defrole groundstation
    ;; declare the variables
    (vars (sc gs name) (payload text))
    ;; trace is what the role does, receives payload
    (trace
      (recv (cat sc payload (hash sc payload (ltk sc gs))))
      )
    )
  )

;; define the skeleton
(defskeleton bsp_integrity
  ;; declare skeleton variables
  (vars (sc gs name))
  ;; define a strand
  (defstrand groundstation 1
    (sc sc) (gs gs))
  ;; the key is a secret and is only known by sc and gs
  (non-orig (ltk sc gs))
  )