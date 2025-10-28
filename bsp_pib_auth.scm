; BSP PIB end-to-end authentication model
; Uses symmetric enc as a stand-in for a MAC under shared key k.

(defprotocol bsp-pib-auth basic
  (defrole src
    (vars (k skey) (pl text) (seq text))
    (trace
      (send (cat pl seq (enc (cat seq pl) k))))
    (non-orig k)
    (uniq-orig seq))
  (defrole dest
    (vars (k skey) (pl text) (seq text))
    (trace
      (recv (cat pl seq (enc (cat seq pl) k)))))
)

(defskeleton bsp-pib-auth
  (vars (k skey) (pl text) (seq text))
  (defstrand dest 1 (k k) (pl pl) (seq seq))
  (non-orig k)
  (uniq-orig seq))
