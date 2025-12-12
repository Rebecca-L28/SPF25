(herald "BSP: PCB Replay Properties"
	(limit 30))

(defprotocol bsp-pcb basic
	;; Initialise each role's SN.
	(defrole seqInit
		(vars (sc gs name) (scSeq gsSeq locn))
		(trace
			;; Initialise spacecraft's SN, force it to be spacecraft's only.
			(stor scSeq (cat "spacecraft" sc gs "0"))
			;; Initialise groundstation's SN, force it to be groundstation's only.
			(stor gsSeq (cat "groundstation" gs sc "0"))))

	;; Spacecraft's role, the sender
	(defrole spacecraft
		(vars (sc gs name) (scSeq locn) (seq mesg) (payload text))
		(trace
			;; Load spacecraft's managed SN
			(load scSeq (cat "spacecraft" sc gs seq))
			;; Send a transmission with the SN, payload consisting of the SN and payload
			;; Encryption -> Payload is encrypted in-place
			;; Key management is out of scope for protocol, but it is a long-term agreed-upon key
			(send (cat sc gs seq (enc payload (ltk sc gs))))
			;; Store the SN + 1 using a hash chain to simulate addition
			(stor scSeq (cat "spacecraft" sc gs (hash "+1" seq))))
		(gen-st scSeq (cat "spacecraft" sc gs seq)))

	;; Ground station's role, the receiver
	(defrole groundstation
		(vars (sc gs name) (gsSeq locn) (seq mesg) (payload text))
		(trace
			;; Receive a transmission with the SN, payload, and MAC consisting of the SN and payload
			(recv (cat sc gs seq (enc payload (ltk sc gs))))
			;; Load groundstation's managed SN
			(load gsSeq (cat "groundstation" gs sc seq))
			;; Store the SN + 1 using a hash chain to simulate addition
			(stor gsSeq (cat "groundstation" gs sc (hash "+1" seq))))
		(gen-st gsSeq (cat "groundstation" gs sc seq)))

	;; Make sure we only have 1 seqInit per role pair, courtesy of Dr. Zieglar
	(defrule only-one-init-per-spacecraft-groundstation-pair
	  (forall ((sc gs name) (z z-0 strd))
		  (implies
		   (and (p "seqInit" z 2) (p "seqInit" z-0 2) (p "seqInit" "sc" z sc) (p "seqInit" "sc" z-0 sc)
			(p "seqInit" "gs" z gs) (p "seqInit" "gs" z-0 gs))
		   (= z z-0)))))

(defskeleton bsp-pcb
	(vars (sc gs name) (payload text))
	(defstrand groundstation 3 (sc sc) (gs gs) (seq "0") (payload payload))
	(defstrand groundstation 3 (sc sc) (gs gs) (seq "0") (payload payload))
	(proceeds ((0 2) (1 0)))
	(non-orig (ltk sc gs))
	(uniq-orig payload))
