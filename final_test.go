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

func TestFinalExploitAttempt(t *testing.T) {
	fmt.Println("=== FINAL EXPLOIT: Weak Fiat-Shamir in GKR ===")
	fmt.Println("Vulnerability: GKR challenges [500, 0] are NOT bound to statement/outputs")
	fmt.Println("Impact: Prover can forge GKR proofs for ANY input/output pairs")
	fmt.Println("")

	// Enable exploit mode
	EXPLOIT_MODE = true
	EXPLOIT_TARGET_BOB = 100000
	defer func() { EXPLOIT_MODE = false }()

	circuit := Circuit{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   100000,  // Claim Bob gets 100k
		NewAliceBalance: 0,        // Alice has 0 left
		Transfer:        500,      // But only transfer 500!
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("❌ Witness failed: %v\n", err)
		t.Fatal(err)
	}

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("❌ Compilation failed: %v\n", err)
		t.Fatal(err)
	}

	fmt.Println("Generating proof with malicious hint...")
	proof, err := groth16.Prove(oR1cs, pk, witness,
		backend.WithSolverOptions(solver.WithHints(TransferHint)))
	if err != nil {
		fmt.Printf("❌ Proving failed: %v\n", err)
		t.Fatal(err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())

	fmt.Println("✅ Proof generated successfully!")
	fmt.Printf("Proof size: %d bytes\n", len(buf.Bytes()))
	fmt.Println("")

	// Verify
	err = VerifyProof("100000", proofHex)
	if err != nil {
		fmt.Printf("❌ Verification failed: %v\n", err)
		t.Fatal(err)
	}

	fmt.Println("🎉🎉🎉 EXPLOIT SUCCESSFUL! 🎉🎉🎉")
	fmt.Println("")
	fmt.Println("The weak Fiat-Shamir vulnerability allowed us to:")
	fmt.Println("- Transfer only 500 tokens")
	fmt.Println("- But claim Bob received 100,000 tokens")
	fmt.Println("- GKR verification passed because challenges aren't bound to outputs!")
	fmt.Println("")
	fmt.Println("Submit to server:")
	fmt.Printf("curl -X GET http://147.182.233.80:8080/ -H \"Content-Type: application/json\" -d '{\"new_bob_balance\": \"100000\", \"proof_hex\": \"%s\"}'\n", proofHex)
}
