package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/sourcekris/goRsaTool/attacks"
	"github.com/sourcekris/goRsaTool/attacks/jwtmodulus"
	"github.com/sourcekris/goRsaTool/attacks/signatures"
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/ln"
	"github.com/sourcekris/goRsaTool/utils"

	fmp "github.com/sourcekris/goflint"
)

var (
	fset           = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	keyFile        = fset.String("key", "", "The filename of the RSA key to attack or dump")
	pastPrimesFile = fset.String("pastprimes", "pastctfprimes.txt", "The filename of a file containing past CTF prime numbers.")
	verboseMode    = fset.Bool("verbose", false, "Enable verbose output.")
	dumpKeyMode    = fset.Bool("dumpkey", false, "Just dump the RSA integers from a key - n,e,d,p,q.")
	createKeyMode  = fset.Bool("createkey", false, "Create a public key given an E and N.")
	exponentArg    = fset.String("e", "", "The exponent value.")
	modulusArg     = fset.String("n", "", "The modulus value.")
	cArg           = fset.String("c", "", "An integer ciphertext.")
	primeArg       = fset.String("p", "", "One of the primes. If provided will shortcut the attack phase and produce a private key.")
	dArg           = fset.String("d", "", "Give d in createkey mode to create a private key.")
	d0Arg          = fset.String("d0", "", "Give LSBs of d, used in partiald attacks.")
	cipherText     = fset.String("ciphertext", "", "An RSA encrypted binary file to decrypt, necessary for certain attacks.")
	numP           = fset.Int("numprimes", 2, "Number of primes expected to be factored.")
	keyList        = fset.String("keylist", "", "Comma seperated list of keys for multi-key attacks.")
	ctList         = fset.String("ctlist", "", "Comma seperated list of ciphertext binaries for multi-key attacks.")
	ptList         = fset.String("ptlist", "", "Comma sepereated list of plaintext files for use in signature mode.")
	sigList        = fset.String("siglist", "", "Comma seperated list of signatures files.")
	jwtList        = fset.String("jwtlist", "", "Comma seperated list of files containing JWTs.")
	hintList       = fset.String("hintlist", "", "Comma seperated list of hints.")
	bruteMax       = fset.String("brutemax", "4096", "Maximum value for brute force related attacks.")
	attack         = fset.String("attack", "all", "Specific attack to try. Specify \"all\" for everything that works unnatended.")
	list           = fset.Bool("list", false, "List the attacks supported by the attack flag.")
	logger         *log.Logger
)

// unnatended will run all supported attacks against t that are listed as working in unnatended mode.
func unnatended(t []*keys.RSA) []error {
	var errs []error
	for _, a := range attacks.SupportedAttacks.Supported {
		if a.Unnatended {
			if err := attacks.SupportedAttacks.Execute(a.Name, t); err != nil {
				errs = append(errs, err)
			}
			for _, k := range t {
				if k.Key.D != nil {
					if k.Verbose {
						logger.Printf("key factored with attack: %v\n", a.Name)
					}
					return nil
				}
			}
		}
	}

	return errs
}

// listAttacks returns a string containing the list of registered attacks.
func listAttacks() string {
	var res string
	for _, a := range attacks.SupportedAttacks.Supported {
		res = fmt.Sprintf("%s%s\n", res, a.Name)
	}

	return res
}

// fileList returns a list of filenames or nil.
func fileList(fl string) []string {
	if fl != "" {
		var fs []string
		for _, k := range strings.Split(fl, ",") {
			fs = append(fs, strings.Trim(k, "\t\n "))
		}
		return fs
	}
	return nil
}

func main() {
	fset.Parse(os.Args[1:])

	var useFlagsForKey bool

	logger = log.New(os.Stderr, "rsatool: ", log.Lshortfile)

	if *verboseMode {
		logger.Println("starting up...")
	}

	if *list {
		fmt.Print(listAttacks())
		return
	}

	// Keep a list of ct, sig, and pt files for later if any of those flags were provided.
	clist := fileList(*ctList)
	klist := fileList(*keyList)
	ptlist := fileList(*ptList)
	siglist := fileList(*sigList)
	jwtlist := fileList(*jwtList)

	// Add the -key flag file to the list if provided.
	if *keyFile != "" {
		klist = append(klist, *keyFile)
	}

	// If no key file or key file list are provided, do we have n and e to make a key up on the fly with?
	if klist == nil {
		if *modulusArg != "" && *exponentArg != "" {
			klist = []string{"ignored"}
			useFlagsForKey = true
		}
	}

	// We need klist and clist to be the same length for now.
	if len(klist) > 0 && len(clist) > 0 && len(klist) != len(clist) {
		log.Fatalf("when using -keylist and -ctlist there should be the same number of files in each list")
	}

	// We got one or more keys to work on, so lets do that.
	if len(klist) > 0 || useFlagsForKey {
		var rsaKeys []*keys.RSA
		for i, kf := range klist {
			var (
				targetRSA *keys.RSA
				nonPemKey bool
				err       error
			)

			if !useFlagsForKey {
				kb, err := ioutil.ReadFile(kf)
				if err != nil {
					log.Fatal(err)
				}
				targetRSA, err = keys.ImportKey(kb)
				if err != nil {
					// Failed to read a valid PEM key. Maybe it is an integer list type key?
					targetRSA, err = keys.ImportIntegerList(kb)
					if err != nil {
						logger.Fatalf("failed reading key file: %v", err)
					}

					nonPemKey = true
				}
			} else {
				// Also include c if it is provided on command line.
				var cliCt []byte
				if *cArg != "" {
					cliCt = ln.NumberToBytes(ln.FmpString(*cArg))
				}
				targetRSA, err = keys.NewRSA(
					keys.PrivateFromPublic(
						&keys.FMPPublicKey{
							N: ln.FmpString(*modulusArg),
							E: ln.FmpString(*exponentArg),
						}), cliCt, nil, "", false)
				if err != nil {
					logger.Fatalf("failed converting modulus and exponent into an RSA key: %v", err)
				}
			}

			targetRSA.PastPrimesFile = *pastPrimesFile
			targetRSA.Verbose = *verboseMode

			var (
				c  []byte
				cf string
			)

			switch {
			case *cipherText != "":
				cf = *cipherText
			case clist != nil:
				cf = clist[i]
			}

			if cf != "" {
				c, err = utils.ReadCipherText(cf)
				if err != nil {
					logger.Fatalf("failed reading ciphertext file: %v", err)
				}

				targetRSA.CipherText = c
			}

			if *d0Arg != "" {
				d0, ok := new(fmp.Fmpz).SetString(*d0Arg, 0)
				if !ok {
					logger.Fatal("failed parsing -d0 flag as an integer")
				}

				targetRSA.DLSB = d0.Bytes()
			}

			if *primeArg != "" {
				p, ok := new(fmp.Fmpz).SetString(*primeArg, 0)
				if !ok {
					logger.Fatal("failed parsing -p flag as an integer")
				}

				targetRSA.Key.Primes = append(targetRSA.Key.Primes, p)
			}

			if *bruteMax != "" {
				bm, err := strconv.Atoi(*bruteMax)
				if err != nil {
					logger.Fatal("failed parsing -brutemax as an integer")
				}
				targetRSA.BruteMax = int64(bm)
			}

			if *hintList != "" {
				hints := strings.Split(*hintList, ",")
				if len(hints) == 0 {
					logger.Fatal("expected at least 1 hint when -hintlist specified")
				}

				for _, hint := range hints {
					targetRSA.Hints = append(targetRSA.Hints, ln.FmpString(hint))
				}
			}

			// Add the key filename, logger and expected number of primes to the key.
			targetRSA.KeyFilename = kf
			targetRSA.Log = logger
			targetRSA.NumPrimes = *numP

			if *dumpKeyMode {
				targetRSA.DumpKey()

				if nonPemKey && targetRSA.Key.PublicKey.E != nil {
					// The input was an integer list key so the user might actually want a PEM dump.
					fmt.Println(keys.EncodeFMPPublicKey(targetRSA.Key.PublicKey))
				}
			}

			rsaKeys = append(rsaKeys, targetRSA)
		}

		if *dumpKeyMode {
			// Job done.
			return
		}

		var errs []error
		switch {
		case *attack == "all" && *primeArg != "":
			errs = append(errs, attacks.SupportedAttacks.Execute("knownprime", rsaKeys))
		case *attack == "all":
			errs = unnatended(rsaKeys)
		case attacks.SupportedAttacks.IsSupported(*attack):
			if *keyList != "" && !attacks.SupportedAttacks.SupportsMulti(*attack) {
				logger.Println("-keylist flag used for attack that does not support multikeys - only the first key will be attacked.")
			}
			errs = append(errs, attacks.SupportedAttacks.Execute(*attack, rsaKeys))
		default:
			errs = []error{fmt.Errorf("unsupported attack: %v. Use -list to see a list of supported attacks", *attack)}
		}

		for _, e := range errs {
			if e != nil {
				logger.Fatal(e)
			}
		}

		// Were we able to solve for any of the private keys or ciphertexts?
		utils.ReportResults(rsaKeys)

		return
	}

	// Recover a modulus from signatures and plaintexts.
	if siglist != nil && ptlist != nil {
		if err := signatures.Attack(ptlist, siglist, *exponentArg); err != nil {
			logger.Fatalf("failed recovering modulus: %v", err)
		}

		// Done.
		return
	}

	// Recover a modulus from two JWTs.
	if jwtlist != nil {
		if err := jwtmodulus.Attack(jwtlist, *exponentArg); err != nil {
			logger.Fatalf("failed recovering modulus: %v", err)
		}

		// Done.
		return
	}

	if *createKeyMode {
		if err := utils.EncodeAndPrintKey(*modulusArg, *exponentArg, *dArg); err != nil {
			logger.Fatal(err)
		}

		return
	}

	logger.Fatal("nothing to do, specify a key with -key or use -help for usage")
}
