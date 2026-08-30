package attacks

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sourcekris/goRsaTool/keys"
)

func TestAttacksRegistrationAndTimeout(t *testing.T) {
	if SupportedAttacks == nil {
		t.Fatal("expected SupportedAttacks to be initialized")
	}

	if len(SupportedAttacks.Supported) == 0 {
		t.Fatal("expected registered attacks in SupportedAttacks")
	}

	if !SupportedAttacks.IsSupported("fermat") {
		t.Error("expected fermat attack to be supported")
	}

	// Verify default timeout on an attack
	defaultTo := SupportedAttacks.GetTimeout("fermat")
	if defaultTo != DefaultTimeout {
		t.Errorf("expected default timeout %d, got %d", DefaultTimeout, defaultTo)
	}

	// Test custom Attacks instance with SetTimeout
	customAttacks := NewAttacks()
	customAttacks.RegisterAttack("dummy", false, true, 50, func(ts []*keys.RSA, ch chan error) {
		ch <- nil
	})

	if customAttacks.GetTimeout("dummy") != 50 {
		t.Errorf("expected dummy timeout 50, got %d", customAttacks.GetTimeout("dummy"))
	}

	// Override timeout on instance
	customAttacks.SetTimeout(10)
	if customAttacks.GetTimeout("dummy") != 10 {
		t.Errorf("expected overridden timeout 10, got %d", customAttacks.GetTimeout("dummy"))
	}
}

func TestExecuteTimeoutOverride(t *testing.T) {
	customAttacks := NewAttacks()

	// Register a slow attack that sleeps for 2 seconds
	customAttacks.RegisterAttack("slow", false, true, 10, func(ts []*keys.RSA, ch chan error) {
		time.Sleep(2 * time.Second)
		ch <- nil
	})

	// Override timeout to 1 second
	customAttacks.SetTimeout(1)

	start := time.Now()
	err := customAttacks.Execute("slow", []*keys.RSA{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected timeout error for slow attack, got nil")
	}

	if !strings.Contains(err.Error(), "failed to factorize the key in the given time") {
		t.Errorf("unexpected error message: %v", err)
	}

	if elapsed > 1800*time.Millisecond {
		t.Errorf("expected timeout around 1s, took %v", elapsed)
	}
}

func TestExecuteSuccessWithinTimeout(t *testing.T) {
	customAttacks := NewAttacks()

	customAttacks.RegisterAttack("fast", false, true, 10, func(ts []*keys.RSA, ch chan error) {
		ch <- nil
	})

	customAttacks.SetTimeout(5)

	err := customAttacks.Execute("fast", []*keys.RSA{})
	if err != nil {
		t.Errorf("expected nil error for fast attack, got %v", err)
	}
}

func TestExecuteUnsupportedAttack(t *testing.T) {
	customAttacks := NewAttacks()

	err := customAttacks.Execute("nonexistent", []*keys.RSA{})
	if err == nil {
		t.Error("expected error for unsupported attack, got nil")
	}
}

func TestExecuteAttackReturningError(t *testing.T) {
	customAttacks := NewAttacks()

	expectedErr := errors.New("custom attack failure")
	customAttacks.RegisterAttack("failing", false, true, 5, func(ts []*keys.RSA, ch chan error) {
		ch <- expectedErr
	})

	err := customAttacks.Execute("failing", []*keys.RSA{})
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}
