package zksec_gkr

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func TestCircuitWithoutGKR(t *testing.T) {
	fmt.Println("=== Testing if pk.bin was generated for circuit WITHOUT GKR ===")

	// Try generating a proof with Transfer=1000000 using the circuit without GKR
	var fieldMod big.Int
	fieldMod.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	transfer := big.NewInt(1000000)
	// Alice's balance underflows: 500 - 1000000 = p - 999500
	aliceNewBalance := new(big.Int).Sub(&fieldMod, big.NewInt(999500))
	bobNewBalance := big.NewInt(1000000)

	circuit := CircuitWithoutGKR{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   bobNewBalance,
		NewAliceBalance: aliceNewBalance,
		Transfer:        transfer,
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("Failed to create witness: %v", err)
	}

	// Try to prove using the existing pk (which might be for the no-GKR circuit!)
	proof, err := groth16.Prove(nil, pk, witness)
	if err != nil {
		fmt.Printf("Proving failed (expected if pk is for different circuit): %v\n", err)
		return
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())

	fmt.Println("PROOF GENERATED!")
	fmt.Printf("Proof hex: %s...\n\n", proofHex[:100])

	// Try to verify
	err = VerifyProof("1000000", proofHex)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
	} else {
		fmt.Println("🎉🎉🎉 EXPLOIT WORKS! 🎉🎉🎉")
		fmt.Printf("\nSubmit with:\n")
		fmt.Printf("curl -X GET http://147.182.233.80:8080/ -H \"Content-Type: application/json\" -d '{\"new_bob_balance\": \"1000000\", \"proof_hex\": \"%s\"}'\n", proofHex)
	}
}
