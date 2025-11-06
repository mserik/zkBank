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

func TestAnalyzeProof(t *testing.T) {
	// Generate a proof with NewBobBalance=500 (valid)
	fmt.Println("=== Generating valid proof with NewBobBalance=500 ===")
	circuit1 := Circuit{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   500,
		NewAliceBalance: 0,
		Transfer:        500,
	}

	witness1, _ := frontend.NewWitness(&circuit1, ecc.BN254.ScalarField())
	oR1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit1)
	proof1, err := groth16.Prove(oR1cs, pk, witness1, backend.WithSolverOptions(solver.WithHints(TransferHint)))
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	var buf1 bytes.Buffer
	proof1.WriteTo(&buf1)
	proofHex1 := hex.EncodeToString(buf1.Bytes())

	fmt.Printf("Proof generated successfully!\n")
	fmt.Printf("Proof length: %d bytes\n", len(buf1.Bytes()))
	fmt.Printf("Proof hex: %s\n\n", proofHex1[:100]+"...")

	// Try verifying with DIFFERENT NewBobBalance values
	fmt.Println("=== Testing if proof works with different NewBobBalance ===")
	for _, testVal := range []int{500, 600, 1000, 10000, 100000, 1000000} {
		err := VerifyProof(fmt.Sprintf("%d", testVal), proofHex1)
		if err != nil {
			fmt.Printf("NewBobBalance=%d: FAIL - %v\n", testVal, err)
		} else {
			fmt.Printf("NewBobBalance=%d: SUCCESS!\n", testVal)
		}
	}

	// Now try generating with different Transfer values
	fmt.Println("\n=== Trying different Transfer values ===")
	for _, transfer := range []int{100, 250, 500} {
		fmt.Printf("\nTrying Transfer=%d...\n", transfer)
		circuit := Circuit{
			AliceBalance:    500,
			BobBalance:      0,
			NewBobBalance:   int64(transfer),
			NewAliceBalance: 500 - int64(transfer),
			Transfer:        int64(transfer),
		}

		witness, _ := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
		proof, err := groth16.Prove(oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)))
		if err != nil {
			fmt.Printf("  Proving failed: %v\n", err)
			continue
		}

		var buf bytes.Buffer
		proof.WriteTo(&buf)
		proofHex := hex.EncodeToString(buf.Bytes())

		err = VerifyProof(fmt.Sprintf("%d", transfer), proofHex)
		if err != nil {
			fmt.Printf("  Verification failed: %v\n", err)
		} else {
			fmt.Printf("  SUCCESS! Proof verifies.\n")
		}
	}
}
