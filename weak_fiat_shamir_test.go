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
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// FINAL EXPLOIT based on weak Fiat-Shamir understanding
// Since the GKR challenges are FIXED (500, 0) and not bound to outputs,
// we can provide ANY outputs and the GKR will accept them!

var maliciousMode = false
var targetBob = big.NewInt(100000)

func MaliciousTransferHint(q *big.Int, inputs []*big.Int, results []*big.Int) error {
	lhs := new(fr.Element).SetBigInt(inputs[0])
	rhs := new(fr.Element).SetBigInt(inputs[1])

	var res fr.Element

	if maliciousMode {
		// For Alice's balance (500 + (-500) = 0)
		if inputs[0].Cmp(big.NewInt(500)) == 0 {
			// Return correct value for Alice
			res.Add(rhs, lhs)
		} else if inputs[0].Cmp(big.NewInt(0)) == 0 {
			// For Bob's balance: claim he gets targetBob instead of 500!
			// With weak Fiat-Shamir, this should pass!
			res.SetBigInt(targetBob)
			fmt.Printf("  Malicious hint: Claiming Bob gets %s (instead of correct 500)\n", targetBob.String())
		} else {
			res.Add(rhs, lhs)
		}
	} else {
		res.Add(rhs, lhs)
	}

	bytes := res.Bytes()
	results[0].SetBytes(bytes[:])

	return nil
}

func TestWeakFiatShamirExploit(t *testing.T) {
	fmt.Println("=== Weak Fiat-Shamir Exploit ===")
	fmt.Println("Bug: GKR challenges [500, 0] are FIXED and not bound to outputs")
	fmt.Println("This allows prover to forge proofs for ANY input/output pairs!")
	fmt.Println("")

	maliciousMode = true
	defer func() { maliciousMode = false }()

	// We claim:
	// - Transfer = 500 (passes <= constraint)
	// - Alice's new balance = 0 (correct: 500 - 500)
	// - Bob's new balance = 100000 (WRONG! Should be 500)

	circuit := Circuit{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   targetBob,      // Claim Bob gets 100k!
		NewAliceBalance: 0,               // Alice correctly has 0
		Transfer:        500,             // Transfer only 500
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("❌ Witness creation failed: %v\n", err)
		t.Fatal(err)
	}

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("❌ Compilation failed: %v\n", err)
		t.Fatal(err)
	}

	fmt.Println("Attempting to prove...")
	proof, err := groth16.Prove(oR1cs, pk, witness,
		backend.WithSolverOptions(solver.WithHints(MaliciousTransferHint)))
	if err != nil {
		fmt.Printf("❌ Proving failed: %v\n", err)
		fmt.Println("")
		fmt.Println("Analysis: The GKR verification still catches the mismatch.")
		fmt.Println("This means the bug might be in a different part of the GKR flow.")
		t.Fatal(err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())

	fmt.Println("✅ Proof generated!")
	fmt.Printf("Proof length: %d bytes\n", len(buf.Bytes()))
	fmt.Printf("Proof hex (first 100 chars): %s...\n", proofHex[:100])
	fmt.Println("")

	// Verify with the server
	err = VerifyProof(targetBob.String(), proofHex)
	if err != nil {
		fmt.Printf("❌ Server verification failed: %v\n", err)
		t.Fatal(err)
	}

	fmt.Println("")
	fmt.Println("🎉🎉🎉 EXPLOIT SUCCESSFUL! 🎉🎉🎉")
	fmt.Println("")
	fmt.Printf("Bob received: %s tokens (from only %d available!)\n", targetBob.String(), 500)
	fmt.Println("")
	fmt.Println("Submit to server:")
	fmt.Printf("curl -X GET http://147.182.233.80:8080/ -H \"Content-Type: application/json\" -d '{\"new_bob_balance\": \"%s\", \"proof_hex\": \"%s\"}'\n",
		targetBob.String(), proofHex)
}
