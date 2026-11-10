package policy

import "testing"

func TestExampleFileIsTheDefault(t *testing.T) {
	p, err := Load("../examples/default.toml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Hash() != Default().Hash() {
		t.Fatalf("examples/default.toml drifted from Default():\n%+v\n%+v", p, Default())
	}
}
