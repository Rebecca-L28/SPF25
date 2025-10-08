;; Add sdls_auth.scm (authorization model for SDLS)
;; Tony Molina
;;
;; Authorization is modeled as an `authz` field included inside the
;; authenticated transmission (MAC). The groundstation (controller)
;; sends (a b command authz tag) where
;;   tag = hash (ltk a b) command authz
;; The spacecraft receives and verifies the tag; because authz is
;; bound inside the MAC, possession of the long-term key is required
;; to produce a valid tag for any desired authz value. Thus an
;; adversary who does not know ltk cannot forge an authorization token.

(defprotocol sdls_auth basic

  ;; Groundstation role (authorized sender / controller)
  (defrole groundstation
    ;; a = groundstation name, b = spacecraft name
    ;; command = action to perform, authz = authorization label (e.g., CONTROLLER)
    (vars (a b name) (command authz text))
    (trace
      ;; groundstation sends command + authz + MAC over them (MAC computed with ltk(a,b))
      (send (cat a b command authz (hash (ltk a b) command authz)))))

  ;; Spacecraft role (verifier / enforcer)
  (defrole spacecraft
    ;; same variables; spacecraft will receive the tuple and only accept it if tag matches
    (vars (a b name) (command authz text))
    (trace
      ;; receive the transmission (a b command authz tag)
      (recv (cat a b command authz (hash (ltk a b) command authz)))
      ;; here we record a fact that can be read in the model / used to indicate acceptance
      ;; (For clarity only — CPSA facts are assertions about the local run.)
      (facts (authorized-received a b command authz))))

  ;; Listener (adversary) role
  (defrole listener
    (vars (x name) (y text))
    (trace
      ;; listener tries to receive any tuple — we want CPSA to check whether
      ;; adversary can obtain a valid (command,authz,tag) pair for some authz
      (recv (cat x y y y))))

)

;; Skeleton(s) to test authorization behavior

;; Skeleton 1: benign authorized command
;; - groundstation (authorized principal) sends command with authz = "CONTROLLER"
;; - spacecraft receives and accepts it
(defskeleton sdls_auth_ok
  (vars (a0 b0 name) (cmd0 auth0 text))

  ;; ground sends: (a0 b0 cmd0 auth0)
  (defstrand groundstation 1
    (a a0) (b b0) (command cmd0) (authz auth0))

  ;; spacecraft receives same tuple
  (defstrand spacecraft 1
    (a a0) (b b0) (command cmd0) (authz auth0))

  ;; mark long-term key uncompromised
  (non-orig (ltk a0 b0))

  ;; ensure auth0 chosen in this run (for example "CONTROLLER")
  (uniq-orig auth0)
)

;; Skeleton 2: adversary tries to impersonate with different authz
;; - listener attempts to present same command but with authz = "UNAUTHORIZED"
;; - because tag covers authz and ltk is secret, CPSA should not realize a strand
;;   where the listener supplies a valid tag for the unauthorized authz
(defskeleton sdls_auth_attack
  (vars (a1 b1 name) (cmd1 authBad text))

  ;; benign original ground send (so tag for authorized authz exists)
  (defstrand groundstation 1
    (a a1) (b b1) (command cmd1) (authz authBad)) ;; note: this models an attacker-chosen authz attempt

  ;; spacecraft receives the (cmd1, authBad, tag) in a second strand
  (defstrand spacecraft 1
    (a a1) (b b1) (command cmd1) (authz authBad))

  ;; mark key secret
  (non-orig (ltk a1 b1))

  ;; unique command or auth to show freshness if needed
  (uniq-orig cmd1)
)
