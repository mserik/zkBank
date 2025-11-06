# Phantom Challenge Analogy to zkBank Bug

## Solana's Phantom Challenge Bug

**The Issue:**
- In Solana's ZK ElGamal Proof Program, a prover-generated challenge value `c_max_proof` was **not absorbed into the Fiat-Shamir transcript**
- This allowed a malicious prover to bypass security checks

**The Fix:**
```
transcript.append_scalar(b"c_max_proof", &c_max_proof);
```

**Impact:** Malicious prover could set arbitrary fee amounts by exploiting the unbound challenge

## zkBank's Analogous Bug

**The Issue:**
```go
// gkr_adder.go:71
err = solution.Verify("mimc", challenges...)

// Where challenges = [circuit.AliceBalance, circuit.BobBalance] = [500, 0]
```

The GKR verifier uses **PUBLIC INPUT values** (500, 0) as base challenges instead of **OUTPUT commitments**.

**What Should Happen (from gnark tests):**
```go
Z := solution.Export(z)  // Get OUTPUT values
challenge, err := api.Compiler().(frontend.Committer).Commit(Z...)
return solution.Verify(hashName, challenge)  // Pass OUTPUT commitment
```

**Key Insight:**
The Fiat-Shamir transcript is seeded with **FIXED PUBLIC VALUES** (500, 0) instead of being bound to the actual computation outputs!

## The Exploitation

### Normal Flow:
1. Prover computes: Alice' = 500 - 500 = 0, Bob' = 0 + 500 = 500
2. Verifier checks: Outputs match commitments bound to transcript challenges
3. ✓ Proof verifies

### With Buggy Challenges:
1. Challenges = [500, 0] are FIXED PUBLIC INPUTS (not bound to outputs!)
2. Prover computes intermediate values via hints
3. GKR verifies using challenges [500, 0]
4. But since 0 is used as a challenge, GKR polynomial evaluation degenerates!

### The Zero Challenge Problem:

When challenge = 0, the Lagrange basis evaluation:
```
eq(x, 0) = Π (1 - xᵢ)
```

This only evaluates to 1 when x = [0,0,...,0], meaning the GKR verification **only checks index 0**!

With 2 additions (indices 0 and 1):
- Index 0 (Alice's balance): VERIFIED ✓
- Index 1 (Bob's balance): NOT VERIFIED! ✗

## Exploitation Strategy

Since BobBalance=0 causes index 1 to not be verified:

1. Set up normal constraints:
   - Transfer = 500 (passes <= check)
   - NewAliceBalance = 0 (will be verified at index 0)
   - NewBobBalance = 1000000 (claim this!)

2. The hint computes Z[0] = 0 (Alice's balance) - VERIFIED
3. The hint should compute Z[1] = 500 (Bob's balance) - NOT VERIFIED due to challenge=0!

4. We need to manipulate Z[1] to be 1000000 instead of 500
5. Since index 1 isn't verified when challenge=0, this should pass!

## Implementation Notes

The bug is in the prover-side GKR hint generation. We need to:
1. Make the TransferHint return 1000000 for Bob's balance (index 1)
2. The GKR Export will return [0, 1000000]
3. The circuit assertions check these values
4. The GKR Verify with challenge=0 won't catch the mismatch at index 1!

BUT: The circuit still has `api.AssertIsEqual(newBobBalance, circuit.NewBobBalance)` which checks the exported value...

So the issue must be more subtle - perhaps the GKR doesn't properly compute Z_gkr when challenge=0?
