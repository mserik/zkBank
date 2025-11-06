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

func TestDebugGKR(t *testing.T) {
	// Let me try swapping the order - what if we put Bob's addition first?
	// Or what if there's an issue with array indexing when challenge=0?

	// Try this: Transfer enough that both balances end up being the same value
	// Maybe the GKR mixes them up when challenge=0?

	var fieldMod big.Int
	fieldMod.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	// If Transfer = 250:
	// Alice: 500 - 250 = 250
	// Bob: 0 + 250 = 250
	// Both end up with 250!

	// What if the GKR with challenge BobBalance=0 can't distinguish between them?
	// And we claim Bob has more?

	transfer := big.NewInt(250)
	aliceNewBalance := big.NewInt(250)
	targetBobBalance := big.NewInt(250)

	circuit := Circuit{
		AliceBalance:    aliceBalance,
		BobBalance:      bobBalance,
		NewBobBalance:   targetBobBalance,
		NewAliceBalance: aliceNewBalance,
		Transfer:        transfer,
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	oR1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("Compilation error:", err)
		t.Fatal(err)
	}

	proof, err := groth16.Prove(
		oR1cs, pk, witness, backend.WithSolverOptions(solver.WithHints(TransferHint)),
	)
	if err != nil {
		fmt.Println("Proving error:", err)
		// Don't fail, let's see what the error is
		fmt.Printf("\nThis is expected - testing if equal balances cause issues...\n")
		return
	}

	fmt.Println("\nProof generated successfully with both balances = 250!")
	fmt.Println("Now let me try to verify with a DIFFERENT Bob balance...")

	// Try to verify the same proof with different values
	var buf bytes.Buffer
	proof.WriteTo(&buf)
	proofHex := hex.EncodeToString(buf.Bytes())

	// Try claiming Bob has more!
	err = VerifyProof("1000000", proofHex)
	if err != nil {
		fmt.Printf("Verification with 1000000 failed: %v\n", err)
	} else {
		fmt.Println("EXPLOIT WORKS!!!")
	}
}
