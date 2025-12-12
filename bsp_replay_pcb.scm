(herald "BSP: PCB Only Replay Properties"
	(limit 100))

(defprotocol bsp-pcb basic
	;; Initialise each role's SN.
	(defrole timeInit
		(vars (timeLoc locn) (sc gs name))
		(trace
			;; Initialise global time
			(stor timeLoc (cat sc gs "0"))))

	;; Tick the time
	(defrole timeTick
		(vars (timeLoc locn) (time mesg) (sc gs name))
		(trace
			;; Load the current time
			(load timeLoc time)
			;; Increase time
			(stor timeLoc (cat sc gs (hash "+1" time))))
		(gen-st timeLoc time))

	;; Spacecraft's role, the sender
	(defrole spacecraft
		(vars (sc gs name) (timeLoc locn) (time mesg) (payload text))
		(trace
			;; Load the global time
			(load timeLoc (cat sc gs time))
			;; Send payload with the current time + signature
			(send (cat sc gs time (enc payload (ltk sc gs)))))
		(gen-st timeLoc (cat sc gs time)))

	;; Ground station's role, the receiver
	(defrole groundstation
		(vars (sc gs name) (timeLoc locn) (time mesg) (payload text))
		(trace
			;; Receive payload with current time
			(recv (cat sc gs time (enc payload (ltk sc gs))))
			;; Load current time
			(load timeLoc (cat sc gs time)))
		(gen-st timeLoc (cat sc gs time)))

	;; Make sure we only have 1 timeInit per role pair, courtesy of Dr. Zieglar
	(defrule only-one-init-per-spacecraft-groundstation-pair
	  (forall ((sc gs name) (z z-0 strd))
		  (implies
		   (and (p "timeInit" z 1) (p "timeInit" z-0 1) (p "timeInit" "sc" z sc) (p "timeInit" "sc" z-0 sc)
			(p "timeInit" "gs" z gs) (p "timeInit" "gs" z-0 gs))
		   (= z z-0)))))


(defskeleton bsp-pcb
	(vars (sc gs name) (payload text))
	(defstrand groundstation 2 (sc sc) (gs gs) (payload payload))
	(defstrand groundstation 2 (sc sc) (gs gs) (payload payload))
	(proceeds ((0 1) (1 0)))
	(non-orig (ltk sc gs))
	(uniq-orig payload)
	)
