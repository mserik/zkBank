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

func TestGenerateProof(t *testing.T) {
	// Generate a valid proof with Bob=500
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
	_, err = proof.WriteTo(&buf)
	if err != nil {
		t.Fatal(err)
	}

	proofHex := hex.EncodeToString(buf.Bytes())
	fmt.Printf("PROOF_HEX: %s\n", proofHex)
}
