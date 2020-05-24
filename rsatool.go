package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/sourcekris/goRsaTool/attacks"
	"github.com/sourcekris/goRsaTool/attacks/signatures"
	"github.com/sourcekris/goRsaTool/keys"
	"github.com/sourcekris/goRsaTool/utils"

	fmp "github.com/sourcekris/goflint"
)

var (
	keyFile        = flag.String("key", "", "The filename of the RSA key to attack or dump")
	pastPrimesFile = flag.String("pastprimes", "pastctfprimes.txt", "The filename of a file containing past CTF prime numbers.")
	verboseMode    = flag.Bool("verbose", false, "Enable verbose output.")
	dumpKeyMode    = flag.Bool("dumpkey", false, "Just dump the RSA integers from a key - n,e,d,p,q.")
	createKeyMode  = flag.Bool("createkey", false, "Create a public key given an E and N.")
	exponentArg    = flag.String("e", "", "The exponent value - for use with createkey flag.")
	modulusArg     = flag.String("n", "", "The modulus value - for use with createkey flag.")
	cipherText     = flag.String("ciphertext", "", "An RSA encrypted binary file to decrypt, necessary for certain attacks.")
	keyList        = flag.String("keylist", "", "Comma seperated list of keys for multi-key attacks.")
	ctList         = flag.String("ctlist", "", "Comma seperated list of ciphertext binaries for multi-key attacks.")
	ptList         = flag.String("ptlist", "", "Comma sepereated list of plaintext files for use in signature mode.")
	sigList        = flag.String("siglist", "", "Comma seperated list of signatures files.")
	attack         = flag.String("attack", "all", "Specific attack to try. Specify \"all\" for everything that works unnatended.")
	list           = flag.Bool("list", false, "List the attacks supported by the attack flag.")
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
	flag.Parse()

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

	// Add the -key flag file to the list if provided.
	if *keyFile != "" {
		klist = append(klist, *keyFile)
	}

	// We need klist and clist to be the same length for now.
	if len(klist) > 0 && len(clist) > 0 && len(klist) != len(clist) {
		log.Fatalf("when using -keylist and -ctlist there should be the same number of files in each list")
	}

	// We got a list of keys to work on, so lets do that.
	if len(klist) > 0 {
		var rsaKeys []*keys.RSA
		for i, kf := range klist {
			var (
				targetRSA *keys.RSA
				nonPemKey bool
			)
			kb, err := ioutil.ReadFile(kf)
			if err != nil {
				log.Fatal(err)
			}

			key, err := keys.ImportKey(kb)
			if err != nil {
				// Failed to read a valid PEM key. Maybe it is an integer list type key?
				targetRSA, err = keys.ImportIntegerList(kb)
				if err != nil {
					logger.Fatalf("failed reading key file: %v", err)
				}

				nonPemKey = true
				targetRSA.PastPrimesFile = *pastPrimesFile
				targetRSA.Verbose = *verboseMode
			}

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
			}

			if targetRSA == nil {
				targetRSA, err = keys.NewRSA(key, c, nil, *pastPrimesFile, *verboseMode)
				if err != nil {
					log.Fatalf("failed to create a RSA key from given key data: %v", err)
				}
			}

			// Add the keyfilename in, helpful later during dumpkey for example.
			targetRSA.KeyFilename = kf
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
				logger.Println(e)
			}
		}

		// Were we able to solve for any of the private keys or ciphertexts?
		for _, k := range rsaKeys {
			if k.Key.D != nil {
				fmt.Println(keys.EncodeFMPPrivateKey(&k.Key))
			}

			if len(k.PlainText) > 0 {
				fmt.Println("Recovered plaintext: ")
				fmt.Println(string(k.PlainText))
			}
		}

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

	if *createKeyMode {
		if len(*exponentArg) > 0 && len(*modulusArg) > 0 {
			n, ok := new(fmp.Fmpz).SetString(*modulusArg, 10)
			if !ok {
				logger.Fatalf("failed converting modulus to integer: %q", *modulusArg)
			}

			e, ok := new(fmp.Fmpz).SetString(*exponentArg, 10)
			if !ok {
				logger.Fatalf("failed converting exponent to integer: %q", *exponentArg)
			}

			pubStr := keys.EncodeFMPPublicKey(&keys.FMPPublicKey{N: n, E: e})
			fmt.Println(pubStr)
			return
		}
		logger.Fatal("no exponent or modulus specified - use -n and -e")
	}

	logger.Fatal("nothing to do, specify a key with -key or use -help for usage")
}
