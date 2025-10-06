;; CCSDS Space Data Link Security (SDLS) Protocol: Replay Protection Properties
;; by Bratt Morejon
;; SPF25

;; SDLS replay-focused abstraction
(defprotocol sdls-replay basic
    ;; Ground station role
    (defrole ground
        ;; Variables of the role:
        ;; a | b = names of the endpoints
        ;; seqNew = new sequence number for this transmission
        ;; frameData = the data of the frame being transmitted
        (vars (a b name) (seqNew frameData text))

        ;; Steps of the role
        (trace
            ;; The role will send a transmission concatenating the new sequence number, the frame data, and the MAC built from k, seqNew, and frameData
            (send (cat seqNew frameData (hash (ltk a b) seqNew frameData)))))

    ;; Spacecraft role
    (defrole spacecraft
        ;; Variables of the role:
        ;; a | b = names of the endpoints
        ;; seqLocation = location of the last known sequence number in memory (Security Association)
        ;; seqOld = value of the old sequence number
        ;; seqNew = value of the new sequence number
        ;; frameData = the data of the frame being transmitted
        (vars (a b name) (seqLocation locn) (seqOld seqNew frameData text))

        ;; Steps of the role
        (trace
            ;; Load the last known sequence number
            (load seqLocation seqOld)
            ;; Receive the transmission of seqNew, frameData, and MAC
            (recv (cat seqNew frameData (hash (ltk a b) seqNew frameData)))
            ;; Store the new sequence number
            (stor seqLocation seqNew))

        ;; seqNew and seqOld cannot be equal, acting as the check for the replay attack
        (facts (neq seqNew seqOld))))

;; Replay attack skeleton
(defskeleton sdls-replay
    ;; Variables for the skeleton:
    ;; a | b = names of the endpoints
    ;; frameData = frameData equivalent
    ;; seqNew = seqNew equivalent
    (vars (a b name) (frameData seqNew text))

    ;; Initial benign transmission by the ground station
    (defstrand ground 1 (a a) (b b) (seqNew seqNew) (frameData frameData))

    ;; Initial receipt of the transmission by the spacecraft
    (defstrand spacecraft 3 (a a) (b b) (seqNew seqNew) (frameData frameData))

    ;; Replay attack in where the same sequence number is sent
    (defstrand spacecraft 3 (a a) (b b) (seqNew seqNew) (frameData frameData))

    ;; Make k secret
    (non-orig (ltk a b))
    ;; Make seqNew unique
    (uniq-orig seqNew))
