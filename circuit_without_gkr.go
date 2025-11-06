package zksec_gkr

import (
	"github.com/consensys/gnark/frontend"
)

// Circuit WITHOUT GKR verification - maybe the pk.bin was generated for this?
type CircuitWithoutGKR struct {
	AliceBalance    frontend.Variable `gnark:",public"`
	BobBalance      frontend.Variable `gnark:",public"`
	NewBobBalance   frontend.Variable `gnark:",public"`
	NewAliceBalance frontend.Variable
	Transfer        frontend.Variable
}

func (circuit *CircuitWithoutGKR) Define(api frontend.API) error {
	// transfer is legit?
	api.AssertIsLessOrEqual(circuit.Transfer, circuit.AliceBalance)

	// new balance for Alice
	negated := api.Neg(circuit.Transfer)
	newAliceBalance := api.Add(circuit.AliceBalance, negated)
	api.AssertIsEqual(newAliceBalance, circuit.NewAliceBalance)

	// new balance for Bob
	newBobBalance := api.Add(circuit.BobBalance, circuit.Transfer)
	api.AssertIsEqual(newBobBalance, circuit.NewBobBalance)

	// NO GKR verification!
	return nil
}
