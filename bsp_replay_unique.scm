;; [RFC 6257] Bundle Security Protocol: Replay Protection Properties
;; Note: Assuming nonce uniqueness is upheld.
;; by Bratt Morejon
;; SPF25

;; BSP replay-focused abstraction, PCB-RSA-AES128-PAYLOAD-PIB-PCB ciphersuite
(defprotocol bsp-replay basic
    ;; Security-Source role
    (defrole sec-src
        ;; Variables of the role:
        ;; bek: bundle encryption key, symmetric
        ;; nonce: salt + IV for this transmission, since AES-GCM, acts as sequence number
        ;; msg: payload
        (vars (bek skey) (nonce msg text))

        ;; Steps of the role
        (trace
            ;; The role will send non-secret nonce, alongside encrypted msg using bek
            (send (cat nonce (enc msg bek)))))

    ;; Security-Destination role
    (defrole sec-dest
        ;; Variables of the role:
        ;; bek: bundle encryption key, symmetric
        ;; nonce: salt + IV for this transmission, since AES-GCM, acts as sequence number
        ;; msg: payload
        (vars (bek skey) (nonce msg text))

        ;; Steps of the role
        (trace
            ;; Receive the transmission of non-secret nonce and encrypted msg using bek
            (recv (cat nonce (enc msg bek))))))

;; Replay attack skeleton
(defskeleton bsp-replay
    ;; Variables for the skeleton:
    ;; bek: bek equivalent
    ;; nonce: nonce equivalent
    ;; msg: msg equivalent
    (vars (bek skey) (nonce msg text))

    ;; Initial benign transmission by security-source
    (defstrand sec-src 1 (bek bek) (nonce nonce) (msg msg))

    ;; Initial receipt of the transmission by the security-destination
    (defstrand sec-dest 1 (bek bek) (nonce nonce) (msg msg))

    ;; Replay attack in where the same nonce is used
    (defstrand sec-dest 1 (bek bek) (nonce nonce) (msg msg))

    ;; Make bek private
    (non-orig bek)
    ;; Make nonce
    (uniq-orig nonce))
