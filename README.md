# SPF25
## CPSA Model Usage
1. **Install the [Haskell Platform](https://www.haskell.org/downloads/)**
3. **Install CPSA**
    ```bash
    cabal update
    cabal install cpsa
    ```
4. **Compile the models with**
    ```bash
    echo build | ghci Make4.hs
    ```
    OR
   ```bash
   python3 run_all_cpsa.py
   ```
6. **The output will be in an .xhtml file such as sdls_replay.xhtml**

## Authors
### University of Florida
Henry Harbone<br>
Rebecca Lee<br>
Tony Molina<br>
Bratt Morejon<br>
Advisor: Cheryl Resch

### National Security Agency
Problem Mentor: Ed Zieglar
