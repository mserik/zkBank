package zksec_gkr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Test if we can just generate a proof with Bob=100000 directly
func TestSimpleHighValue(t *testing.T) {
	fmt.Println("=== Simple Test: Can we prove Bob gets 100,000? ===")

	// What if the bug allows us to just claim Bob=100000 with Transfer=500?
	// The GKR verification with wrong challenges might not catch it!

	circuit := Circuit{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   100000,
		NewAliceBalance: -99500, // This would be invalid normally
		Transfer:        500,
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("❌ Witness creation failed: %v\n", err)
		return
	}

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("❌ Compilation failed: %v\n", err)
		return
	}

	proof, err := groth16.Prove(oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)))
	if err != nil {
		fmt.Printf("❌ Proving failed: %v\n", err)
		return
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())

	fmt.Println("✓ Proof generated!")

	err = VerifyProof("100000", proofHex)
	if err != nil {
		fmt.Printf("❌ Verification failed: %v\n", err)
	} else {
		fmt.Println("🎉🎉🎉 EXPLOIT WORKS!")
		fmt.Printf("\nSubmit with:\n")
		fmt.Printf("curl -X GET http://147.182.233.80:8080/ -H \"Content-Type: application/json\" -d '{\"new_bob_balance\": \"100000\", \"proof_hex\": \"%s\"}'\n", proofHex)
	}
}

// Test with field wrap-around for Alice's balance
func TestFieldWrapAround(t *testing.T) {
	fmt.Println("\n=== Test: Field Wrap-Around ===")

	var fieldMod big.Int
	fieldMod.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// Alice's balance wraps: 500 - 100000 = p - 99500
	aliceNew := new(big.Int).Sub(&fieldMod, big.NewInt(99500))

	circuit := Circuit{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   100000,
		NewAliceBalance: aliceNew,
		Transfer:        100000,
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("❌ Witness creation failed: %v\n", err)
		return
	}

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("❌ Compilation failed: %v\n", err)
		return
	}

	proof, err := groth16.Prove(oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)))
	if err != nil {
		fmt.Printf("❌ Proving failed: %v\n", err)
		return
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())

	fmt.Println("✓ Proof generated!")

	err = VerifyProof("100000", proofHex)
	if err != nil {
		fmt.Printf("❌ Verification failed: %v\n", err)
	} else {
		fmt.Println("🎉🎉🎉 EXPLOIT WORKS!")
		fmt.Printf("\nSubmit with:\n")
		fmt.Printf("curl -X GET http://147.182.233.80:8080/ -H \"Content-Type: application/json\" -d '{\"new_bob_balance\": \"100000\", \"proof_hex\": \"%s\"}'\n", proofHex)
	}
}
