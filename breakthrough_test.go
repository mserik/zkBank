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

// BREAKTHROUGH: Server verification sets Transfer=0 and NewAliceBalance=0!
// It only checks public inputs: AliceBalance, BobBalance, NewBobBalance
// So we need to find a proof that satisfies the circuit with our values!

func TestBreakthrough(t *testing.T) {
	fmt.Println("=== BREAKTHROUGH ATTEMPT ===")
	fmt.Println("Server verification only checks public inputs!")
	fmt.Println("Transfer and NewAliceBalance are set to 0 during verification")
	fmt.Println("")

	var fieldMod big.Int
	fieldMod.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// Try Transfer = 100000
	// Alice: 500 - 100000 = p - 99500 (underflow)
	// Bob: 0 + 100000 = 100000

	transfer := big.NewInt(100000)
	aliceNew := new(big.Int).Sub(&fieldMod, big.NewInt(99500))
	bobNew := big.NewInt(100000)

	circuit := Circuit{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   bobNew,
		NewAliceBalance: aliceNew,
		Transfer:        transfer,
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

	fmt.Println("Attempting to prove with Transfer=100000...")
	proof, err := groth16.Prove(oR1cs, pk, witness,
		backend.WithSolverOptions(solver.WithHints(TransferHint)))
	if err != nil {
		fmt.Printf("❌ Proving failed: %v\n", err)
		return  // Don't fatal, just report
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())

	fmt.Println("✅ Proof generated!")
	fmt.Println("")

	// Try to verify
	err = VerifyProof("100000", proofHex)
	if err != nil {
		fmt.Printf("❌ Verification failed: %v\n", err)
		t.Fatal(err)
	}

	fmt.Println("🎉🎉🎉 EXPLOIT SUCCESSFUL! 🎉🎉🎉")
	fmt.Println("")
	fmt.Printf("curl -X GET http://147.182.233.80:8080/ -H \"Content-Type: application/json\" -d '{\"new_bob_balance\": \"100000\", \"proof_hex\": \"%s\"}'\n", proofHex)
}
