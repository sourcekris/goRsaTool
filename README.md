# goRsaTool

goRsaTool is an RSA tool for CTF challenges, it attempts multiple attacks against a public key 
and/or an RSA encrypted ciphertext binary in an effort to recover either the private key, the plain
text of the message or both.

Inspired by my time spent contributing to [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) and
originally for the purpose of learning golang. Now I maintain this tool as a side project with the
goal of support as wide a range of factorization methods and RSA attacks as possible.

## Attacks supported in this version

### Single Key Attacks
* factordb attack (i.e. is the modulus already fully factored on factordb.com)
* small q attack
* novelty primes attack
* past CTF primes attack
* fermat factorization for close p & q
* low public exponent attack (requires ciphertext)
* wiener's attack for large public exponents (3 variants)
* pollards p-1 attack
* williams p+1 attack
* pollards rho factorization - original Pollard's Monte Carlo factorization method
* pollard rho brent factorization - Richard Brents improved version of Pollard's monte carlo 
  factorization
* Qi Cheng factorization from "A New Class of Unsafe Primes"
* solve for plaintext with CRT components provided (Dp, Dq, p, q, c)
* ecm (Lenstra elliptic curve method) - Not as good as other implementations at the moment though.
* Franklin Reiter related message attack - Requires 1 key, 2 ciphertexts which are related with some
  minor different suffix. See the example keys in the examples/ subdirectory.
* small fraction factorization - finding factors of n when p and q are close to a small fraction 
  (e.g. 37/32).

### Multi-Key Attacks
* hastads broadcast attack
* common factors attack (share p among multiple moduli)
* common modulus attack (2 keys share n but have different e)

## Installation
 * Requires go 1.9 +
 * Get dependencies, you will need:
    * Golang
    * Git
    * FLINT2 (Fast Library for Number Theory)
    * This works on Debian, Ubuntu (tested 20.04 LTS) and Windows 10 WSL 2.0 (tested in Debian WSL)
    ```
    sudo apt install git golang libflint-dev
    ```
 * Get Golang libraries this uses:
   ```
   go get github.com/jbarham/primegen
   go get github.com/sourcekris/goflint
   go get github.com/sourcekris/x509big
   ```
 * Download and build this tool using go install repo and build:
   ```
   $ go get github.com/sourcekris/goRsaTool
   $ go install github.com/sourcekris/goRsaTool
   $ $HOME/go/bin/goRsaTool -h
    Usage of /home/username/go/bin/goRsaTool:
      -attack string
          Specific attack to try. Specify "all" for everything that works unnatended. (default 
          "all")
      -ciphertext string
          An RSA encrypted binary file to decrypt, necessary for certain attacks.
      -createkey
          Create a public key given an E and N.
      -ctlist string
          Comma seperated list of ciphertext binaries for multi-key attacks.
      -dumpkey
          Just dump the RSA integers from a key - n,e,d,p,q.
      -e string
          The exponent value - for use with createkey flag.
      -key string
          The filename of the RSA key to attack or dump
      -keylist string
          Comma seperated list of keys for multi-key attacks.
      -list
          List the attacks supported by the attack flag.
      -n string
          The modulus value - for use with createkey flag.
      -pastprimes string
          The filename of a file containing past CTF prime numbers. (default "../pastctfprimes.txt")
      -verbose
          Enable verbose output.
   ```

## Usage:

### Generate a public key
```
$ ./gorsatool -createkey -n 115367564564210182766242534110944507919869313713243756429 -e 3
-----BEGIN RSA PUBLIC KEY-----
MB0CGAS0flryFxnpDN8t2jlPVnTt6YdoEyEXjQIBAw==
-----END RSA PUBLIC KEY-----
```

### Dump the parameters from a key
```
$ ./gorsatool -dumpkey -key ./key.pub
key.pub:
n = 115367564564210182766242534110944507919869313713243756429
e = 3
```
### Attack a public key
```
$ ./gorsatool -key ./key.pub -attack all -verbose
rsatool: rsatool.go:72: starting up...
2020/05/13 21:48:28 fermat factorization attempt beginning with timeout 5m0s
2020/05/13 21:53:28 small q attempt beginning with timeout 3m0s
rsatool: rsatool.go:45: key factored with attack: smallq
-----BEGIN RSA PRIVATE KEY-----
MEoCAQACGAS0flryFxnpDN8t2jlPVnTt6YdoEyEXjQIBAwIBAAIDM7EfAhUXTSkV
Ec7+LmR48UUVuXtlKE1fhdMCAQACAQACAxw+pw==
-----END RSA PRIVATE KEY-----
```

### Attack a public key thats a list of numbers
```
$ cat numbers.txt
n = 115367564564210182766242534110944507919869313713243756429
e = 3
$ ./gorsatool -key numbers.txt -attack ecm -verbose
rsatool: rsatool.go:72: starting up...
2020/05/13 21:50:31 ecm factorization attempt beginning with timeout 5m0s
-----BEGIN RSA PRIVATE KEY-----
MEoCAQACGAS0flryFxnpDN8t2jlPVnTt6YdoEyEXjQIBAwIBAAIDM7EfAhUXTSkV
Ec7+LmR48UUVuXtlKE1fhdMCAQACAQACAxw+pw==
-----END RSA PRIVATE KEY-----
```

### List available attacks
```
$ ./gorsatool -list
crtsolver
factordb
fermat
hastads
hastadsbroadcast
novelty
pastctf
smallq
wiener
pollardsp1
pollardsrho
pollardrhobrent
williamsp1
qicheng
ecm
commonfactors
commonmodulus
franklinreiter
smallfractions
```

## More Example Usage 

### Attack a public key with a specific attack:
`./gorsatool -key ./key.pub -attack wiener`

### Attack the example pollards p-1 key with the pollards p-1 attack:
`./gorsatool -key examples/pollardsp1.pub -attack pollardsp1`

### Attack multiple keys with a hastads broadcast attack
`./gorsatool -keylist examples/hastadsbroadcast1.key,examples/hastadsbroadcast2.key,examples/hastadsbroadcast3.key -attack hastadsbroadcast`

## Author

* Kris Hunt (@ctfkris)
