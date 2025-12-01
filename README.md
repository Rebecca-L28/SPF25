# SPF25
Cryptographic protocols often fail to meet their intended security goals, and there are flaws in standards as well as insecure implementations. There is a need for formal verification in space network communication protocols provided by the Consultative Committee for Space Data Systems (CCSDS).  Our team addressed these problems by modeling the security properties of the Space Data Link Security (SDLS) and Bunde Security (BSP) Protocols using CPSA. We also built C implementations of these protocols to test attacks against. Current work with formal verification for communication protocols focuses on mathematically modeling security. In our project, we demonstrate not only mathematical models but also an implementation that allows for different attack scenarios to be tested. 

We opted to separate the mathematical models and implementations in this repository for easier viewing.

## CPSA
Our CPSA models are in the ```cpsa``` branch. The instructions to run the source code are there.

## C Implementations
Our C implementations are in the ```prototype``` branch. The instructions to run the source code are there.
