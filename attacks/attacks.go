package attacks

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sourcekris/goRsaTool/attacks/brokenrsa"
	"github.com/sourcekris/goRsaTool/attacks/commonfactor"
	"github.com/sourcekris/goRsaTool/attacks/commonmodulus"
	"github.com/sourcekris/goRsaTool/attacks/crt"
	"github.com/sourcekris/goRsaTool/attacks/defectivee"
	"github.com/sourcekris/goRsaTool/attacks/factordb"
	"github.com/sourcekris/goRsaTool/attacks/fermat"
	"github.com/sourcekris/goRsaTool/attacks/franklinreiter"
	"github.com/sourcekris/goRsaTool/attacks/gmpecm"
	"github.com/sourcekris/goRsaTool/attacks/hastads"
	"github.com/sourcekris/goRsaTool/attacks/hastadsbroadcast"
	"github.com/sourcekris/goRsaTool/attacks/knownprime"
	"github.com/sourcekris/goRsaTool/attacks/londahl"
	"github.com/sourcekris/goRsaTool/attacks/manysmallprimes"
	"github.com/sourcekris/goRsaTool/attacks/notableprimes"
	"github.com/sourcekris/goRsaTool/attacks/oraclemodulus"
	"github.com/sourcekris/goRsaTool/attacks/partiald"
	"github.com/sourcekris/goRsaTool/attacks/pastctfprimes"
	"github.com/sourcekris/goRsaTool/attacks/pollardrhobrent"
	"github.com/sourcekris/goRsaTool/attacks/pollardsp1"
	"github.com/sourcekris/goRsaTool/attacks/pollardsrho"
	"github.com/sourcekris/goRsaTool/attacks/qicheng"
	"github.com/sourcekris/goRsaTool/attacks/smallfractions"
	"github.com/sourcekris/goRsaTool/attacks/smallq"
	"github.com/sourcekris/goRsaTool/attacks/squaren"
	"github.com/sourcekris/goRsaTool/attacks/wiener"
	"github.com/sourcekris/goRsaTool/attacks/wienermultiprime"
	"github.com/sourcekris/goRsaTool/attacks/williamsp1"
	"github.com/sourcekris/goRsaTool/keys"
)

// default timeout 3m0s
const DefaultTimeout int = 180

// SupportedAttacks stores the list of registered attacks we support.
var SupportedAttacks *Attacks

func init() {
	SupportedAttacks = NewAttacks()
	// TODO(sourcekris): Register them in each package init function.
	SupportedAttacks.RegisterAttack("crtsolver", false, true, DefaultTimeout, crt.Attack)
	SupportedAttacks.RegisterAttack("factordb", false, true, DefaultTimeout, factordb.Attack)
	SupportedAttacks.RegisterAttack("hastads", false, true, DefaultTimeout, hastads.Attack)
	SupportedAttacks.RegisterAttack("hastadsbroadcast", true, true, DefaultTimeout, hastadsbroadcast.Attack)
	SupportedAttacks.RegisterAttack("commonfactors", true, true, DefaultTimeout, commonfactor.Attack)
	SupportedAttacks.RegisterAttack("commonmodulus", true, true, DefaultTimeout, commonmodulus.Attack)
	SupportedAttacks.RegisterAttack("partiald", false, false, DefaultTimeout, partiald.Attack)
	SupportedAttacks.RegisterAttack("knownprime", false, false, DefaultTimeout, knownprime.Attack)
	SupportedAttacks.RegisterAttack("brokenrsa", false, true, DefaultTimeout, brokenrsa.Attack)
	SupportedAttacks.RegisterAttack("notableprimes", false, true, DefaultTimeout, notableprimes.Attack)
	SupportedAttacks.RegisterAttack("pastctf", false, true, DefaultTimeout, pastctfprimes.Attack)
	SupportedAttacks.RegisterAttack("smallq", false, true, DefaultTimeout, smallq.Attack)
	SupportedAttacks.RegisterAttack("wiener", false, true, DefaultTimeout, wiener.Attack)
	SupportedAttacks.RegisterAttack("wienermultiprime", false, true, DefaultTimeout, wienermultiprime.Attack)
	SupportedAttacks.RegisterAttack("qicheng", false, true, DefaultTimeout, qicheng.Attack)
	SupportedAttacks.RegisterAttack("fermat", false, true, DefaultTimeout, fermat.Attack)
	SupportedAttacks.RegisterAttack("londahl", false, true, DefaultTimeout, londahl.Attack)
	SupportedAttacks.RegisterAttack("smallfractions", false, true, DefaultTimeout, smallfractions.Attack)
	SupportedAttacks.RegisterAttack("manysmallprimes", false, true, DefaultTimeout, manysmallprimes.Attack)
	SupportedAttacks.RegisterAttack("ecm", false, true, DefaultTimeout, gmpecm.Attack)
	SupportedAttacks.RegisterAttack("franklinreiter", true, true, DefaultTimeout, franklinreiter.Attack)
	SupportedAttacks.RegisterAttack("pollardsp1", false, true, DefaultTimeout, pollardsp1.Attack)
	SupportedAttacks.RegisterAttack("pollardsrho", false, true, DefaultTimeout, pollardsrho.Attack)
	SupportedAttacks.RegisterAttack("pollardrhobrent", false, true, DefaultTimeout, pollardrhobrent.Attack)
	SupportedAttacks.RegisterAttack("williamsp1", false, true, DefaultTimeout, williamsp1.Attack)
	SupportedAttacks.RegisterAttack("defectivee", false, true, DefaultTimeout, defectivee.Attack)
	SupportedAttacks.RegisterAttack("oraclemodulus", false, true, DefaultTimeout, oraclemodulus.Attack)
	SupportedAttacks.RegisterAttack("squaren", false, true, DefaultTimeout, squaren.Attack)

	// Aliased attacks (names that point to attacks already in the above list).
	SupportedAttacks.RegisterAttack("mersenne", false, false, DefaultTimeout, notableprimes.Attack)
	SupportedAttacks.RegisterAttack("lucas", false, false, DefaultTimeout, notableprimes.Attack)
	SupportedAttacks.RegisterAttack("novelty", false, false, DefaultTimeout, notableprimes.Attack)
	SupportedAttacks.RegisterAttack("pastprimes", false, false, DefaultTimeout, pastctfprimes.Attack)
	SupportedAttacks.RegisterAttack("pastctfprimes", false, false, DefaultTimeout, pastctfprimes.Attack)
	SupportedAttacks.RegisterAttack("sexyprimes", false, false, DefaultTimeout, fermat.Attack)
}

type attackFunc func([]*keys.RSA, chan error)

// Attack encodes a single attack and what features it supports.
type Attack struct {
	Name          string
	SupportsMulti bool
	Unnatended    bool
	Timeout       int
	F             attackFunc
}

// Attacks wraps a slice of Attack objects that are supported.
type Attacks struct {
	Supported []*Attack
}

// NewAttacks constructs a new Attacks object.
func NewAttacks() *Attacks {
	return &Attacks{}
}

// RegisterAttack adds a new attack to the receiving Attacks.
func (a *Attacks) RegisterAttack(name string, multi bool, unnatended bool, timeout int, f attackFunc) {
	if a == nil {
		a = NewAttacks()
	}

	a.Supported = append(a.Supported, &Attack{name, multi, unnatended, timeout, f})
}

// IsSupported returns true if name attack is supported.
func (a *Attacks) IsSupported(name string) bool {
	for _, a := range a.Supported {
		if a.Name == name {
			return true
		}
	}

	return false
}

// SupportsMulti returns true if the attack supports multi-key attacks.
func (a *Attacks) SupportsMulti(name string) bool {
	for _, a := range a.Supported {
		if a.Name == name {
			return a.SupportsMulti
		}
	}

	return false
}

// Execute executes the named attack against t.
func (a *Attacks) Execute(name string, t []*keys.RSA) error {
	if SupportedAttacks == nil {
		return errors.New("no attacks registered")
	}

	if !a.IsSupported(name) {
		return fmt.Errorf("unsupported attack: %v", name)
	}

	for _, a := range SupportedAttacks.Supported {
		if a.Name == name {
			ctx := context.Background()
			ctx, cancel := context.WithTimeout(ctx, time.Duration(a.Timeout*int(time.Second)))
			defer cancel()

			ch := make(chan error)

			go a.F(t, ch)

			select {
			case result := <-ch:
				return result
			case <-ctx.Done():
				return fmt.Errorf("%s failed to factorize the key in the given time", name)
			}
		}
	}

	return errors.New("attack not found")
}
