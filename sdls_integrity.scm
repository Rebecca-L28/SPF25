;; CPSA model for SDLS integrity, it uses abstract MAC tags
;; Rebecca Lee

;; defines protocol called sdls_integrity using basic algebra
(defprotocol sdls_integrity basic

  ;; defines spacescraft role
  (defrole spacecraft
    ;; declare the variables
    ;; sc is name of spacecraft, message is the message, and tag is the abstracted MAC tag
    (vars (sc name) (message text) (tag text))
    ;; trace is what this role actually does, sends identity, message, and tag
    (trace
      (send (cat sc message tag))))

  ;; defines groundstation role
  (defrole groundstation
    ;; declare the variables
    ;; sc is name of spacecraft, message is the message, and tag is the abstracted MAC tag
    (vars (sc name) (message text) (tag text))
    ;; trace is what this role actually does, recieves identity, message, and tag
    (trace
      (recv (cat sc message tag))))

  ;; defines listener role (adversary)
  (defrole listener
    ;; declare the variables
    ;; sc is name of spacecraft, x is the message, and tag is the abstracted MAC tag
    (vars (sc name) (x text) (tag text))
    ;; trace is what this role actually does
    ;; recieves identity, x message, and tag
    ;; the listener is trying to recieve the altered message because SDLS integrity allows for the message to be observed by unauthorized people but it cannot be altered, as the CPSA model will show
    (trace
      (recv (cat sc x tag))))
)

;; define the skeleton
(defskeleton sdls_integrity
  ;; declare variables
  ;; sc0 is the spacecraft name, msg0 is the message, t0 is the abstracted MAC tag
  (vars (sc0 name) (msg0 text) (t0 text))

  ;; this strand sends (sc0, msg0, t0)
  (defstrand spacecraft 1
    (sc sc0) (message msg0) (tag t0))

  ;; this strand recieves (sc0, msg0, t0)
  (defstrand groundstation 1
    (sc sc0) (message msg0) (tag t0))

  ;; this strand attepts to recieve (sc0, msg0, t0)
  ;; it tests also whether or not the listener can tamper with the message
  ;; this strand test will test if CPSA can realize a strand where the listener can see a valid MAC tag with a different/tampered with message
  ;; if CPSA can't it means that the MAC tag is bound to the original message msg0 and integrity holds
  (defstrand listener 1
    (sc sc0) (x msg0) (tag t0))
)
