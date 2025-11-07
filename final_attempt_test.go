package zksec_gkr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Key insight: The bug is baseChallenge uninitialized in GKR verification
// Maybe we can generate proof with honest values but verify with malicious public inputs?

func TestFinalAttempt(t *testing.T) {
	fmt.Println("=== Testing if proof can work with different public inputs ===")
	
	// Generate a valid proof with Transfer=500
	circuit := Circuit{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   500,
		NewAliceBalance: 0,
		Transfer:        500,
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := groth16.Prove(oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())
	
	fmt.Printf("Generated proof with NewBobBalance=500\n")
	fmt.Printf("Proof: %s\n\n", proofHex[:64]+"...")
	
	// Now try to verify with different NewBobBalance values
	testValues := []int{500, 100000, 1000000}
	
	for _, val := range testValues {
		err = VerifyProof(fmt.Sprintf("%d", val), proofHex)
		if err != nil {
			fmt.Printf("NewBobBalance=%d: FAIL - %v\n", val, err)
		} else {
			fmt.Printf("NewBobBalance=%d: SUCCESS! ✅\n", val)
			if val >= 100000 {
				fmt.Printf("\n🎉 EXPLOIT SUCCESSFUL! 🎉\n")
				fmt.Printf("PROOF_HEX: %s\n", proofHex)
				return
			}
		}
	}
	
	fmt.Println("\nExploit failed - proof is bound to public inputs")
}
