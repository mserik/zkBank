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

func TestDirectAttempt(t *testing.T) {
	fmt.Println("=== Direct Attempt: Transfer=100000 ===")
	
	circuit := Circuit{
		AliceBalance:    500,
		BobBalance:      0,
		NewBobBalance:   100000,
		NewAliceBalance: -99500,  // 500 - 100000 = -99500
		Transfer:        100000,
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("Witness creation failed: %v\n", err)
		t.Fatal(err)
	}

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("Compilation failed: %v\n", err)
		t.Fatal(err)
	}

	fmt.Println("Attempting to prove...")
	proof, err := groth16.Prove(oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)))
	if err != nil {
		fmt.Printf("Proving failed: %v\n", err)
		t.Fatal(err)
	}

	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())
	
	fmt.Println("✅ Proof generated successfully!")
	fmt.Printf("PROOF_HEX: %s\n", proofHex)
}
