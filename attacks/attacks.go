package attacks

import (
	"errors"
	"fmt"

	"github.com/sourcekris/goRsaTool/keys"
)

// SupportedAttacks stores the list of registered attacks we support.
var SupportedAttacks *Attacks

func init() {
	SupportedAttacks = NewAttacks()
	// TODO(sewid): Move attacks to their own packages and register them in each package init function.
	SupportedAttacks.RegisterAttack("factordb", false, true, FactorDB)
	SupportedAttacks.RegisterAttack("fermat", false, true, FermatFactorization)
	SupportedAttacks.RegisterAttack("hastads", false, true, Hastads)
	SupportedAttacks.RegisterAttack("novelty", false, true, NoveltyPrimes)
	SupportedAttacks.RegisterAttack("pastctf", false, true, PastCTFPrimes)
	SupportedAttacks.RegisterAttack("smallfractions", false, false, SmallFractions)
	SupportedAttacks.RegisterAttack("smallq", false, true, SmallQ)
	SupportedAttacks.RegisterAttack("wiener", false, true, Wiener)
}

type attackFunc func(*keys.RSA) error

// Attack encodes a single attack and what features it supports.
type Attack struct {
	Name          string
	SupportsMulti bool
	Unnatended    bool
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
func (a *Attacks) RegisterAttack(name string, multi bool, unnatended bool, f attackFunc) {
	if a == nil {
		a = NewAttacks()
	}

	a.Supported = append(a.Supported, &Attack{name, multi, unnatended, f})
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

// Execute executes the named attack against t.
func (a *Attacks) Execute(name string, t *keys.RSA) error {
	if SupportedAttacks == nil {
		return errors.New("no attacks registered")
	}

	if !a.IsSupported(name) {
		return fmt.Errorf("unsupported attack: %v", name)
	}

	for _, a := range SupportedAttacks.Supported {
		if a.Name == name {
			return a.F(t)
		}
	}

	return errors.New("attack not found")
}
