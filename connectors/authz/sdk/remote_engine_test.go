package sdk

import "testing"

func TestNewRemoteEnginePanicsOnNilClient(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil client")
		}
	}()

	_ = NewRemoteEngine(nil)
}
