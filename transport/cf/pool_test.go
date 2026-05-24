package cf

import "testing"

func TestPoolNextClientRoundRobin(t *testing.T) {
	a := &Client{}
	b := &Client{}
	c := &Client{}
	p := newPoolFromClients([]*Client{a, b, c})

	got := []*Client{
		p.nextClient(),
		p.nextClient(),
		p.nextClient(),
		p.nextClient(),
		p.nextClient(),
	}
	want := []*Client{a, b, c, a, b}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("selection %d = %p, want %p", i, got[i], want[i])
		}
	}
}
