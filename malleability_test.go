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

func TestMalleability(t *testing.T) {
	// Generate a valid proof with NewBobBalance = 500
	circuit := Circuit{
		AliceBalance:    aliceBalance,
		BobBalance:      bobBalance,
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

	proof, err := groth16.Prove(
		oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)),
	)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}
	proofHex := hex.EncodeToString(buf.Bytes())

	// Now try to verify with DIFFERENT NewBobBalance values!
	fmt.Println("\n=== Testing Public Input Malleability ===")

	testValues := []string{"500", "1000", "10000", "100000", "1000000"}
	for _, val := range testValues {
		fmt.Printf("\nTrying NewBobBalance = %s with the same proof...\n", val)
		err = VerifyProof(val, proofHex)
		if err != nil {
			fmt.Printf("  FAILED: %v\n", err)
		} else {
			fmt.Printf("  SUCCESS! The proof verifies with NewBobBalance = %s\n", val)
			if val == "1000000" {
				fmt.Println("\n🎉 EXPLOIT FOUND! We can claim Bob has 1,000,000 tokens!")
				fmt.Printf("\nSubmit with:\n")
				fmt.Printf("curl -X GET http://147.182.233.80:8080/ -H \"Content-Type: application/json\" -d '{\"new_bob_balance\": \"%s\", \"proof_hex\": \"%s\"}'\n",
					val, proofHex)
			}
		}
	}
}
