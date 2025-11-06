# zkBank Vulnerability Analysis

## The Bug

The vulnerability is in how challenges are passed to the GKR verifier.

### Correct Usage (from gnark tests)
```go
Z := solution.Export(z)  // Get OUTPUT values
return solution.Verify(hashName, Z...)  // Pass OUTPUTS as challenges
```

Or with commitment:
```go
Z := solution.Export(z)
challenge, err := api.Compiler().(frontend.Committer).Commit(Z...)
return solution.Verify(hashName, challenge)
```

### Buggy Usage (in zkBank)
```go
// app.go:81
err := gkrBalance.VerifyGKR(circuit.AliceBalance, circuit.BobBalance)

// gkr_adder.go:71
err = solution.Verify("mimc", challenges...)  // Passes INPUT values (500, 0)
```

## The Issue

The zkBank code passes **PUBLIC INPUT** values (AliceBalance=500, BobBalance=0) as base challenges to the Fiat-Shamir transcript, instead of commitments to the **OUTPUT** values.

When BobBalance=0 is used as a base challenge:
1. The Fiat-Shamir transcript is seeded with (500, 0)
2. This affects the randomness generation for the GKR verification
3. The zero value may cause the polynomial evaluations to degenerate
4. This breaks the soundness of the proof system

## The Fix (in gnark v0.10.0)

The fix "assign baseChallenge correctly while verifying gkr solution" ensures that the base challenges are properly assigned during verification, likely by using OUTPUT commitments instead of arbitrary input values.

## Exploitation Strategy

Since the current implementation has buggy verification, we need to understand what proof would:
1. PASS the buggy verification (with challenge=0)
2. Give Bob >= 100,000 tokens

The key insight: If the GKR verification is broken when challenge=0, then the assertions at gkr_adder.go:77 might not properly verify Bob's balance calculation.

We need to find witness values where:
- Transfer <= 500 (passes the constraint)
- NewAliceBalance = claimed value
- NewBobBalance = 1,000,000
- The broken GKR verification passes

