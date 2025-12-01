# SPF25
## Prototype Usage
0. **Enter prototype folder.**
   ```bash
    cd ./prototype/
   ```
2. **Compile the program.**
    ```bash
    make
    ```
3. **Choose whether to test the Bundle Security (BSP) or the Space Data Link Security Protocol (SDLS)**:
4. **For BSP, simply start the corresponding showcase file**:
    ```bash
    ./bundle/bundle
    ```
5. **For SDLS, simply start the corresponding showcase file**.
    ```bash
    ./sdls/sdls
    ```
6. **Follow instructions of the program to begin testing of the protocols.**

SDLS allows for multiple tests in one command execution, while BSP will close itself after running a test. Both allow for custom tests that can be in found in either ```./sdls/sdls_showcase.c``` or ```./bundle/bundle.c``` in ```choice8()``` and ```choice7()``` respectively, if more specific testing wants to be accomplished.

## Authors
### University of Florida<br>
Henry Harbone<br>
Rebecca Lee<br>
Tony Molina<br>
Bratt Morejon<br>
Advisor: Cheryl Resch

### National Security Agency<br>
Problem Mentor: Ed Zieglar
