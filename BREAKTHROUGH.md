# BREAKTHROUGH: Understanding the Exploit

## The Key Insight

The GKR verification happens DURING PROVING, not just during final verification!

### Flow:

1. **Proving Phase:**
   - Circuit Define() runs
   - AddCircuit() stores X, Y values and calls TransferHint for Z
   - VerifyGKR() runs:
     - Imports X, Y into GKR
     - Calls `solution.Solve()` which uses a HINT to compute outputs
     - Calls `solution.Verify()` with challenges (500, 0)
     - Asserts our Z values match GKR-computed values

2. **The Bug:**
   - `solution.Verify("mimc", challenges...)` where challenges = [500, 0]
   - When challenge=0, the polynomial evaluation eq(x, [500, 0]) degenerates!
   - This breaks the soundness of GKR verification

3. **The Exploitation:**
   - The `Solve()` hint computes the GKR outputs
   - The `Verify()` checks those outputs with challenge=0 (BROKEN!)
   - Our TransferHint provides Z values
   - AssertIsEqual checks Z == Z_gkr

## The Problem with My Previous Attempts

I was modifying TransferHint, but that's the WRONG hint!

The hints are:
- **TransferHint**: Computes our local Z values (used by AddCircuit)
- **GKR SolveHint**: Computes the GKR outputs (used by solution.Solve)
- **GKR ProveHint**: Generates the GKR proof (used by solution.Verify)

The GKR hints are PLACEHOLDERS in the code! They're registered by gnark internally.

## The Real Bug

Looking at compile.go:127-131:
```go
outsSerialized, err := parentApi.Compiler().NewHint(SolveHintPlaceholder, solveHintNOut, ins...)
api.toStore.SolveHintID = solver.GetHintID(SolveHintPlaceholder)
```

The SolveHintPlaceholder is replaced at runtime with the actual GKR solver.

When challenge=0, the GKR verification doesn't properly check all outputs, so the GKR solver can return WRONG values that still pass verification!

## What We Need to Do

We CAN'T modify the GKR hints directly (they're internal to gnark).

BUT: If the bug allows wrong Z_gkr values to pass verification, then:
1. We set NewBobBalance = 1000000 in our witness
2. The TransferHint returns Z[1] = 1000000
3. The GKR Solve hint ALSO returns Z_gkr[1] = 1000000
4. The GKR Verify with challenge=0 FAILS TO CATCH THIS!
5. AssertIsEqual passes because Z[1] == Z_gkr[1] == 1000000

But wait - the GKR circuit is `z = Add(x, y)` where x=[500, 0] and y=[(-500), 500]

The GKR Add gate should compute z=[0, 500] regardless of hints!

## Re-examining the GKR API

Looking at api.go:31-33:
```go
func (api *API) Add(i1, i2 constraint.GkrVariable, in ...constraint.GkrVariable) constraint.GkrVariable {
	return api.namedGate2PlusIn("add", i1, i2, in...)
}
```

This creates a GKR wire with an ADD gate. The gate's output is DEFINED by the gate logic, not by hints!

So how do hints work? Looking at compile.go:127:
```go
outsSerialized, err := parentApi.Compiler().NewHint(SolveHintPlaceholder, solveHintNOut, ins...)
```

The hint is used to SOLVE the circuit! So the hint must compute what the outputs SHOULD be.

## The Actual Vulnerability

The vulnerability must be that:
1. The Solve hint computes outputs based on inputs
2. The Verify checks the proof with challenge=0
3. When challenge=0, Verify doesn't properly verify all outputs
4. So WRONG outputs from Solve can pass Verify!

This means we need to see if we can provide malicious INPUTS to the GKR circuit that result in our desired outputs when Solve runs!

But we're providing X=[500, 0] and Y=[(-500), 500] which are fixed by our circuit constraints...

Unless... what if we provide WRONG Y values that aren't actually (-Transfer) and (Transfer)?
