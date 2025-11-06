# Final Understanding of the zkBank Exploit

## The Constraints

1. **Transfer ≤ 500**: `api.AssertIsLessOrEqual(circuit.Transfer, circuit.AliceBalance)`
2. **Alice's Balance**: `api.AssertIsEqual(gkrBalance.AddCircuit(500, -Transfer), circuit.NewAliceBalance)`
3. **Bob's Balance**: `api.AssertIsEqual(gkrBalance.AddCircuit(0, Transfer), circuit.NewBobBalance)`
4. **GKR Verification**: `gkrBalance.VerifyGKR(500, 0)`

## The Logical Impossibility

From constraint 3:
- `newBobBalance = AddCircuit(0, Transfer) = TransferHint(0, Transfer) = 0 + Transfer`
- `newBobBalance == circuit.NewBobBalance` (asserted)
- Therefore: `NewBobBalance == Transfer`

From constraint 1:
- `Transfer ≤ 500`

Therefore:
- `NewBobBalance ≤ 500`

**This makes Bob getting 100,000 tokens logically impossible!**

## The Bug Must Be

Since the constraints are sound, the bug must be in the GKR verification at gkr_adder.go:70-78:

```go
Z_gkr := solution.Export(z)  // GKR computes outputs
err = solution.Verify("mimc", challenges...)  // Verify with (500, 0)
...
for i := 0; i < m.counter; i++ {
    m.api.AssertIsEqual(m.Z[i], Z_gkr[i])  // Assert hint values match GKR
}
```

**Hypothesis**: When challenge=0, the GKR `solution.Export(z)` returns INCORRECT values that still pass `solution.Verify()`!

Specifically:
- `Z_gkr[0]` (Alice's balance) is computed correctly as 0
- `Z_gkr[1]` (Bob's balance) is computed INCORRECTLY due to challenge=0 bug

If `Z_gkr[1]` returns the CLAIMED value (100000) instead of the CORRECT value (500), and `Verify()` passes due to challenge=0 breaking soundness, then:

1. Our hint returns Z[1] = 100000 (what we claim)
2. GKR Export returns Z_gkr[1] = 100000 (WRONG, but challenge=0 allows it)
3. GKR Verify passes (challenge=0 breaks soundness)
4. Assertion Z[1] == Z_gkr[1] passes (both are 100000)
5. Assertion newBobBalance == NewBobBalance passes (both are 100000)

## The Missing Piece

I still don't understand HOW `solution.Export(z)` returns wrong values.

The GKR circuit is:
- x = Import([500, 0])  // Alice's and Bob's initial balances
- y = Import([(-Transfer), Transfer])  // Changes
- z = Add(x, y)  // New balances

The Add gate should compute:
- z[0] = x[0] + y[0] = 500 + (-Transfer)
- z[1] = x[1] + y[1] = 0 + Transfer

The Solve() hint computes these values. How can it return wrong values?

Unless... the hint itself is wrong? Or the Export permutation is wrong when challenge=0?

Or maybe the bug is that we need to provide WRONG input values to the GKR circuit?

## Next Steps

1. Try generating a proof where we provide y[1] = 100000 instead of Transfer
2. See if the GKR verification with challenge=0 doesn't catch the mismatch
3. This would allow Z_gkr[1] = 0 + 100000 = 100000 to pass verification
