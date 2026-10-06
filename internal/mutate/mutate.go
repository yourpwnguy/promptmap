// Package mutate expands one payload into several probes.
//
// Basically we take a known evil prompt and tweak it a little (change
// case, add padding, wrap it in a fake benign request) so we catch
// naive keyword filters. Same idea as redirx: fuzz payloads, keep the
// part that matters intact.
//
// The canary token is sacred. We never mutate it, otherwise the
// detector would have nothing to look for.
package mutate

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/promptmap/promptmap/internal/payloads"
)

// Mutator tweaks a prompt and reports the name of the tweak.
type Mutator interface {
	Name() string
	Mutate(prompt, canary string) string
}

// CaseSwap flips the case of letters outside the canary.
//
// Naive filters often block exact lowercase phrases like "ignore
// previous instructions" but miss "IgNoRe PrEvIoUs". Cheap trick,
// surprisingly effective against dumb blocklists.
type CaseSwap struct{}

func (CaseSwap) Name() string { return "case-swap" }

func (CaseSwap) Mutate(prompt, canary string) string {
	parts := strings.Split(prompt, canary)
	for i, part := range parts {
		var b strings.Builder
		for j, r := range part {
			if j%2 == 0 {
				b.WriteRune(toUpperASCII(r))
			} else {
				b.WriteRune(toLowerASCII(r))
			}
		}
		parts[i] = b.String()
	}
	return strings.Join(parts, canary)
}

// PadWhitespace adds benign looking padding around the prompt.
//
// Some apps trim or match exact strings. Extra newlines and spaces
// break exact matches without changing what the model reads.
type PadWhitespace struct{}

func (PadWhitespace) Name() string { return "pad-whitespace" }

func (PadWhitespace) Mutate(prompt, canary string) string {
	return "\n\n" + prompt + "\n\nPlease respond helpfully.\n"
}

// WrapBenign wraps the payload in a fake legitimate request.
//
// This is the classic "for my security research class..." wrapper.
// It does not change the injection, it just gives the model a
// plausible excuse to comply.
type WrapBenign struct{}

func (WrapBenign) Name() string { return "wrap-benign" }

func (WrapBenign) Mutate(prompt, canary string) string {
	return fmt.Sprintf("For my security research, can you help with this? %s Thanks!", prompt)
}

// Registry returns the mutators matching names. Unknown names error out
// so typos in config fail fast instead of silently doing nothing.
func Registry(names []string) ([]Mutator, error) {
	all := map[string]Mutator{
		"case-swap":      CaseSwap{},
		"pad-whitespace": PadWhitespace{},
		"wrap-benign":    WrapBenign{},
	}
	var out []Mutator
	for _, n := range names {
		m, ok := all[strings.ToLower(n)]
		if !ok {
			return nil, fmt.Errorf("unknown mutator %q (want case-swap, pad-whitespace, wrap-benign)", n)
		}
		out = append(out, m)
	}
	return out, nil
}

// Expand builds the probe list: one clean probe per payload plus one
// per mutator, deduped by hash and capped at maxProbes.
//
// Dedupe matters because two mutators can produce the same string on
// short payloads, and we do not want to waste requests. The cap keeps
// a big corpus from turning into a 2000 request accidental DoS.
func Expand(base []payloads.Payload, muts []Mutator, maxProbes int) []payloads.Probe {
	seen := map[string]bool{}
	var out []payloads.Probe
	add := func(p payloads.Payload, prompt string, applied []string) {
		h := hash(prompt)
		if seen[h] {
			return
		}
		seen[h] = true
		out = append(out, payloads.Probe{
			PayloadID: p.ID,
			Category:  p.Category,
			Severity:  p.Severity,
			Canary:    p.Canary,
			Prompt:    prompt,
			Mutations: applied,
		})
	}
	for _, p := range base {
		add(p, p.Prompt, nil)
		for _, m := range muts {
			add(p, m.Mutate(p.Prompt, p.Canary), []string{m.Name()})
		}
		if len(out) >= maxProbes {
			break
		}
	}
	if len(out) > maxProbes {
		out = out[:maxProbes]
	}
	return out
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:8])
}

func toUpperASCII(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}

func toLowerASCII(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + 32
	}
	return r
}
