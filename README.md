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
* small q attack (`smallq`)
* novelty primes attack - 31337 and 1337 primes. (`notableprimes`)
* mersenne primes - factor n when p is a mersenne prime (`notableprimes`)
* lucas primes - factor n when p is a lucas prime (`notableprimes`)
* past CTF primes attack (`pastctfprimes`)
* fermat factorization for close p & q (`fermat`)
* londahl factorization for close p & q (`londahl`)
* low public exponent attack (requires ciphertext) (`hastads`)
* wiener's attack for large public exponents (3 variants) (`wiener`)
* wiener's attack on multiprime RSA (`wiener`)
* pollards p-1 attack (`pollardsp1`)
* williams p+1 attack (`williamsp1`)
* pollards rho factorization - original Pollard's Monte Carlo factorization method (`pollardsrho`)
* pollard rho brent factorization - Richard Brents improved version of Pollard's monte carlo 
  factorization (`pollardsrhobrent`)
* Qi Cheng factorization from "A New Class of Unsafe Primes" (`qicheng`)
* solve for plaintext with CRT components provided (Dp, Dq, p, q, c)
* ecm (Lenstra elliptic curve method) using GMP-ECM library (`ecm`)
* Franklin Reiter related message attack - Requires 1 key, 2 ciphertexts which are related with some
  minor different suffix. See the example keys in the examples/ subdirectory. (`franklinreiter`)
* small fraction factorization - finding factors of n when p and q are close to a small fraction 
  (e.g. 37/32). (`smallfractions`)
* faulty rsa implementation where c = me mod n instead of ct = m^e mod n (`brokenrsa` module)
* Public key consisting of many small primes (corCTF 2021 4096 challenge) (`manysmallprimes`)
* Private key recovery when 50+% of the LSB of D are known. (`partiald`)
* Sexy primes - primes seperated by 6. (`fermat`)
* Known prime - not really an attack but a helpful shortcut (`knownprime`)
* Recovering plaintext when phi(n) are not coprime provided we have at least 1 prime and partial KPT (`defectivee`)

### Multi-Key Attacks

* hastads broadcast attack (`hastadsbroadcast`)
* common factors attack (share p among multiple moduli) (`commonfactors`)
* common modulus attack (2 keys share n but have different e) (`commonmodulus`)

### Non Key Based Tools

* recover RSA modulus given signatures and plaintexts (use `-siglist` flag)
* recover RSA modulus given an encryption oracle (`oraclemodulus`, see `examples/recover_modulus_from_oracle.txt`)
* recover RSA modulus given two RS256 JWT tokens (`jwtmodulus`).

## Installation

* Requires go 1.9 +
* Get dependencies, you will need:
  * Golang
  * Git
  * FLINT2 (Fast Library for Number Theory)
  * GMP-ECM (GMP Elliptic Curve Method factorization)

### Installation on Linux / Windows 10

This works on Ubuntu (tested 20.04 LTS) and Windows 10 WSL 2.0 (tested in Ubuntu20.04 WSL)
as well as Kali Linux 2021.3.

  ```shell
  sudo apt install git golang libflint-dev libecm-dev make
  git clone github.com/sourcekris/goRsaTool
  cd goRsaTool
  make
  make install
  ```

Note: If your environment GOBIN variable is not set it will not install automatically. Either set your 
      GOBIN environment variable or move the binary by hand somewhere in your path.

### Installing on OSX

For Mac OSX (tested on Mojave) you need Golang installed. I used the official .pkg distrubution from
the Golang homepage. To install dependencies I used [Homebrew](https://brew.sh/) to install FLINT 
and built GMP-ECM library from source. This guide assumes Xcode is already setup / working.

#### Install FLINT

Install FLINT first, it comes with GMP which is a dependancy of GMP-ECM.

```shell
$ brew install flint
```

#### Building GMP-ECM on OSX

There's no prepackaged version of GMP-ECM on OSX. There is a MacPorts gmp-ecm package but it is only
the ecm binary and does not include the headers needed. To install GMP-ECM from source follow these
steps.

```shell
$ cd ~
$ mkdir Math
$ svn co svn://scm.gforge.inria.fr/svn/ecm/trunk $HOME/Math/ecm
...
$ cd ecm/Math
$ brew install autoconf automake libtool
$ glibtoolize
$ autoreconf -i
$ ./configure --with-gmp=/usr/local/
$ make
$ make install
```

Finally, get the goRsaTool package

```shell
$ go get github.com/sourcekris/goRsaTool
```

## Usage

### Generate a public key

```shell
$ ./gorsatool -createkey -n 115367564564210182766242534110944507919869313713243756429 -e 3
-----BEGIN RSA PUBLIC KEY-----
MB0CGAS0flryFxnpDN8t2jlPVnTt6YdoEyEXjQIBAw==
-----END RSA PUBLIC KEY-----
```

### Dump the parameters from a key

```shell
$ ./gorsatool -dumpkey -key ./key.pub
key.pub:
n = 115367564564210182766242534110944507919869313713243756429
e = 3
```

### Attack a public key

```shell
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

```shell
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

```shell
$ ./gorsatool -list
crtsolver
factordb
hastads
hastadsbroadcast
commonfactors
commonmodulus
partiald
knownprime
brokenrsa
notableprimes
pastctf
smallq
wiener
wienermultiprime
qicheng
fermat
londahl
smallfractions
manysmallprimes
ecm
franklinreiter
pollardsp1
pollardsrho
pollardrhobrent
williamsp1
defectivee
oraclemodulus
mersenne
lucas
novelty
pastprimes
pastctfprimes
sexyprimes
```

## More Example Usage

### Attack a public key with a specific attack

`./gorsatool -key ./key.pub -attack wiener`

### Attack the example pollards p-1 key with the pollards p-1 attack

`./gorsatool -key examples/pollardsp1.pub -attack pollardsp1`

### Attack multiple keys with a hastads broadcast attack

`./gorsatool -keylist examples/hastadsbroadcast1.key,examples/hastadsbroadcast2.key,examples/hastadsbroadcast3.key -attack hastadsbroadcast`

### Recover an RSA Modulus From RSA Signatures and Plaintexts

`./rsatool -ptlist message1.txt,message2.txt -siglist sig1,sig2`

Note: See the `test.sh` file for more examples using almost every attack in the list.

## Author

* Kris Hunt (@ctfkris)
