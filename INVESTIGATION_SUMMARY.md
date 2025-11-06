# zkBank Investigation Summary

## ✅ Confirmed Vulnerability

**Weak Fiat-Shamir in GKR Implementation**

### The Bug
- **Location**: `gkr_adder.go:71` - `solution.Verify("mimc", challenges...)`
- **Issue**: GKR verification uses FIXED PUBLIC INPUT values `[AliceBalance=500, BobBalance=0]` as Fiat-Shamir challenges instead of binding them to computation outputs
- **Fix**: gnark v0.10.0 (PR #1020) - "assign baseChallenge correctly while verifying gkr solution"

### Analogous Vulnerabilities
1. **Phantom Challenge** (Solana ZK ElGamal): Challenge not absorbed into transcript
2. **zkLighter Audit** (zkSecurity): "Prover can forge GKR proofs for any input/output pairs when initial randomness not strongly linked to statement"

### Correct Usage (from gnark tests)
```go
Z := solution.Export(z)  // Get OUTPUT values
challenge, err := api.Compiler().(frontend.Committer).Commit(Z...)  // Commit to outputs
return solution.Verify(hashName, challenge)  // Use committed challenge
```

### Buggy Usage (zkBank)
```go
err = solution.Verify("mimc", circuit.AliceBalance, circuit.BobBalance)  // Uses INPUT values!
```

## 🔍 Circuit Constraint Analysis

### Public Inputs
- AliceBalance = 500
- BobBalance = 0
- NewBobBalance (user-provided)

### Private Values
- NewAliceBalance
- Transfer

### Constraints
1. `Transfer ≤ AliceBalance` (500)
2. `NewAliceBalance == GKR.Add(500, -Transfer)`
3. `NewBobBalance == GKR.Add(0, Transfer)`
4. `GKR.Verify(500, 0)`

### Logical Implication
From constraints 1 & 3: **NewBobBalance ≤ 500**

This makes Bob receiving ≥100,000 tokens logically impossible with honest computation!

## ❌ Exploitation Barrier

### Attempted Approaches
1. **Malicious TransferHint**: Returning wrong values → GKR internal assertion `Z[i] == Z_gkr[i]` catches mismatch
2. **Field Underflow**: Transfer > 500 → Fails `AssertIsLessOrEqual` during proving
3. **Direct High Values**: NewBobBalance = 100000, Transfer = 500 → GKR computes correct value (500), assertion fails
4. **Weak F-S Exploitation**: Modified hint to return 100000 → Still caught by Z[i] == Z_gkr[i] check

### The Core Problem
The weak Fiat-Shamir SHOULD allow forging GKR proofs, but gnark's implementation still has the assertion:
```go
for i := 0; i < m.counter; i++ {
    m.api.AssertIsEqual(m.Z[i], Z_gkr[i])  // This catches our malicious values!
}
```

Even if `solution.Verify()` passes with broken challenges, this assertion compares:
- `Z[i]`: Our hint-provided value
- `Z_gkr[i]`: GKR-computed value (still correct!)

## 💡 Possible Missing Pieces

### Theory 1: GKR Export Permutation Bug
When challenge=0, `solution.Export(z)` might return values in wrong order due to permutation issues:
```go
return algo_utils.Map(s.permutations.SortedInstances, ...)
```

### Theory 2: GKR Solve Hint Malleability
The internal `SolveHintPlaceholder` might be exploitable, but it's not directly accessible.

### Theory 3: Different Exploitation Path
Maybe the bug allows something other than direct balance manipulation?

### Theory 4: Proving Key Mismatch
The `pk.bin` might be for a slightly different circuit version?

## 📊 Progress Made

### Identified
- ✅ Root cause: Weak Fiat-Shamir (challenges not bound to outputs)
- ✅ Analogous vulnerabilities in other systems
- ✅ Correct vs buggy usage patterns
- ✅ Complete constraint analysis

### Created
- Multiple test files exploring attack vectors
- Detailed documentation of findings
- Modified TransferHint for exploitation attempts

### Not Achieved
- ❌ Working proof generating Bob ≥ 100,000 tokens
- ❌ Understanding exact mechanism to bypass Z[i] == Z_gkr[i] check
- ❌ Successfully exploiting the weak Fiat-Shamir vulnerability

## 🎯 Conclusion

The vulnerability is **confirmed to exist** based on:
1. It matches the description of known weak Fiat-Shamir bugs
2. It was fixed in gnark v0.10.0
3. The zkBank version (v0.9.2) predates the fix

However, **exploitation remains elusive** because gnark's GKR implementation includes internal consistency checks (`Z[i] == Z_gkr[i]`) that catch malicious values even when the weak Fiat-Shamir allows the proof verification to pass.

The exact exploitation technique likely requires deeper understanding of:
- How gnark's GKR permutations work with challenge=0
- Whether there's a way to make GKR Solve return malicious values
- Or if there's a completely different attack vector

This challenge demonstrates the subtlety of cryptographic implementation bugs - knowing the vulnerability exists doesn't automatically reveal how to exploit it.
