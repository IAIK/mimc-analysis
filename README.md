# Higher-Order Differential Analysis of MiMC
This repository contains the attack code for the analysis of the MiMC block cipher.

## Code
- zero_sum_tester.cpp

This file is used to find zero sums for MiMC.

Compile with:

`g++ -std=c++0x -g -O2 -funroll-loops -march=native -mtune=native zero_sum_tester.cpp -o zero_sum_tester -lcrypto -lm`

Use with:

`./zero_sum_tester`

- Magma_Script_MiMC_Univariate_Attack

This Magma file contains the attack. It has two input parameters "N" and "version". The first specifies which block size should be used, while "version" specifies the attack (r_{KR} = 1 or r_{KR} = 2). The script outputs the roots of the polynomial F(K), as well as the secret key for comparison.
