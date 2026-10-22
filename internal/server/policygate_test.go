package server

import (
	"testing"
	"time"
)

func TestPolicyGuardChannelThreshold(t *testing.T) {
	var g policyGuard
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for i := 0; i < policyChannelThreshold-1; i++ {
		if g.noteChannelRefusedAt("global", now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("guard opened early at hit %d", i+1)
		}
	}
	if !g.noteChannelRefusedAt("global", now.Add(time.Duration(policyChannelThreshold)*time.Second)) {
		t.Fatal("guard should open at threshold")
	}
	got := g.blockedAt("global", now.Add(2*time.Second))
	if !got.Blocked || got.Reason != "channel_refused" {
		t.Fatalf("guard status=%+v", got)
	}
	if g.blockedAt("global", got.Until).Blocked {
		t.Fatal("guard should expire at until boundary")
	}
}

func TestPolicyGuardAccountRestrictionNeedsDistinctAccounts(t *testing.T) {
	var g policyGuard
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	if g.noteAccountRestrictedAt("global", "u1", now) {
		t.Fatal("single account must not open guard")
	}
	if g.noteAccountRestrictedAt("global", "u1", now.Add(time.Second)) {
		t.Fatal("same account must not count twice")
	}
	if !g.noteAccountRestrictedAt("global", "u2", now.Add(2*time.Second)) {
		t.Fatal("two distinct restricted accounts should open guard")
	}
	got := g.blockedAt("global", now.Add(3*time.Second))
	if !got.Blocked || got.Reason != "account_restricted" {
		t.Fatalf("guard status=%+v", got)
	}
}
