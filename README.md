# goRsaTool

A golang port of [RsaCtfTool](https://github.com/sourcekris/RsaCtfTool) for the express purposes of learning go.

RsaCtfTool is an RSA tool for CTF challenges, it attempts multiple attacks against a public key in an effort to recover either the private key, the plain text of the message or both.

Attacks supported in this go version:

* factordb attack (i.e. is the modulus already fully factored on factordb.com)
* small q attack

## Installation
Get dependencies:
`go get github.com/kavehmz/prime"` 

## Usage:

### Generate a public key :
`./gorsatool -createkey -n 7828374823761928712873129873981723...12837182 -e 65537`

### Dump the parameters from a key:
`./gorsatool -dumpkey -key ./key.pub`
