# zkBank Challenge - Solution Attempt

## Understanding the Challenge

**Goal**: Make Bob receive >= 100,000 tokens when Alice only has 500 tokens.

**Key Vulnerability**: The GKR verification uses `BobBalance = 0` as one of the challenges in `VerifyGKR(circuit.AliceBalance, circuit.BobBalance)`.

## Circuit Analysis

The circuit performs:
1. Checks `Transfer <= AliceBalance` (500)
2. Computes Alice's new balance: `500 + (-Transfer)`
3. Computes Bob's new balance: `0 + Transfer`
4. Verifies both computations using GKR with challenges `(500, 0)`

## Vulnerability Hypothesis

Using 0 as a cryptographic challenge in GKR proof systems can break soundness because:
- In multilinear polynomial evaluation, a challenge of 0 can cause degenerate cases
- The Lagrange interpolation may only verify a subset of the additions
- With 2 additions at binary indices (00, 01), a zero challenge for the second bit might skip verification of index 01 (Bob's balance)

## Approaches Attempted

### 1. Malicious Hint Function
- **Idea**: Modify `TransferHint` to return incorrect values (e.g., 1,000,000 instead of 500 for Bob's balance)
- **Result**: Failed - GKR still computes correct values and assertions catch the mismatch
- **Error**: `constraint #3544 is not satisfied: 1000000 != 500`

### 2. Field Arithmetic Underflow
- **Idea**: Use Transfer = p - 99,500 (representing -99,500 in field arithmetic)
- **Result**: Failed - gnark correctly interprets as negative and fails `AssertIsLessOrEqual`
- **Error**: `[mustBeLessOrEq] -500 <= 500`

### 3. Public Input Malleability
- **Idea**: Generate proof with one NewBobBalance, verify with different value
- **Result**: Failed - proof properly binds to public inputs
- **Error**: `pairing doesn't match` for different values

### 4. Large Transfer with Underflow
- **Idea**: Transfer = 1,000,000, causing Alice's balance to underflow
- **Result**: Failed - constraint check prevents large transfers
- **Error**: `[mustBeLessOrEq] 1000000 <= 500`

### 5. Circuit Without GKR
- **Idea**: Check if pk.bin was generated for circuit without GKR verification
- **Result**: Failed - unrecognized curve type when trying to prove with mismatched circuit

## Current Blocker

The fundamental issue is that even if the GKR verification with challenge=0 is broken:
1. The GKR.Add() operation still computes correct element-wise addition
2. The Export() returns the correctly computed values
3. The assertions `m.api.AssertIsEqual(m.Z[i], Z_gkr[i])` catch any mismatches

The hint can return wrong values, but the GKR-computed values remain correct, causing assertion failures during proof generation.

## Potential Solution Direction

The vulnerability likely involves:
- Understanding how gnark's GKR implementation specifically handles zero challenges
- Finding a way to make the GKR Export return incorrect values when Verify is broken
- Or discovering a completely different vulnerability related to circuit constraints being underspecified

## Files Modified

- `gkr_adder.go`: Attempted malicious hint modifications (reverted)
- `exploit_test.go`: Various exploitation attempts
- `malleability_test.go`: Public input malleability tests
- `analyze_proof_test.go`: Proof structure analysis
- `circuit_without_gkr.go`: Alternative circuit without GKR
- `without_gkr_test.go`: Testing key mismatch hypothesis

## Next Steps for Future Investigation

1. Study gnark's GKR source code to understand exact behavior with zero challenges
2. Analyze whether the Verify() failure affects Export() output
3. Check for version-specific bugs in gnark v0.9.2
4. Investigate if there's a way to manipulate the GKR solution object
5. Consider if the vulnerability is in a completely different part of the code

## Conclusion

While I've identified that using BobBalance=0 as a GKR challenge is suspicious and likely the vulnerability, I was unable to successfully exploit it to generate a valid proof with NewBobBalance >= 100,000. The challenge requires deeper understanding of gnark's GKR implementation internals.
