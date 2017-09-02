package utils

import (
  "testing"
)

func TestIsInt(t *testing.T) {
  if !IsInt("12345") {
    t.Errorf("12345 wasnt classified as an Int!\n")
  }

  if IsInt("abcd") {
    t.Errorf("abcd was classified as an Int!\n")
  }

  if IsInt("!@#$^*(*)") {
    t.Errorf("Special characters were an Int!\n")
  }
}

