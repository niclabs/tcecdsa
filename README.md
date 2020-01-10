# Threshold Cryptography Eliptic Curve Digital Signature Algorithm

[![Go Report Card](https://goreportcard.com/badge/github.com/niclabs/tcecdsa?a=0)](https://goreportcard.com/report/github.com/niclabs/tcecdsa)
[![Build Status](https://travis-ci.org/niclabs/tcecdsa.svg?branch=master&a=0)](https://travis-ci.org/niclabs/tcecdsa)
[![GoDoc](https://godoc.org/github.com/niclabs/tcecdsa?status.svg&a=0)](https://godoc.org/github.com/niclabs/tcecdsa)

Implementation of Threshold Cryptography Eliptic Curve Digital Signature Algorithm proposed on the paper 
[Using Level-1 Homomorphic Encryption To Improve Threshold DSA Signatures For Bitcoin Wallet Security](http://www.cs.haifa.ac.il/~orrd/LC17/paper72.pdf).


This implementation is loosely based on the 
[extension of Paillier Toolbox to use Level-2 Homomorphic Encryption](https://github.com/citp/ThresholdECDSA) from Princeton CITP. 
That code is the working example of the work in the paper mentioned earlier.
 
This code also implements the level-2 homomorphic encryption protocol from Dario Catalano et al,
[Boosting Linearly-Homomorphic Encryption to Evaluate Degree-2 Functions on Encrypted Data](https://eprint.iacr.org/2014/813.pdf).

# Requirements

The only requirement for this library is our [Threshold Paillier Implementation] (https://github.com/niclabs/tcpaillier). It will be downloaded automatically if the module is used with [Go Modules](https://blog.golang.org/using-go-modules)

# Using the library

To use the library with a module-enabled go project, you must write the following line on a terminal on the root file of the project.

```bash
go get github.com/niclabs/tcecdsa
```

# Tests

To run the tests you just need to use go test:

```bash
go test github.com/niclabs/tcecdsa
```
