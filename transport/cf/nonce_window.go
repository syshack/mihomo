package cf

import "sync"

const nonceWindowBits = 64

type nonceState struct {
	maxNonce    uint32
	seenMask    uint64
	initialized bool
}

type NonceWindow struct {
	mu     sync.Mutex
	states map[uint32]*nonceState
}

func NewNonceWindow() *NonceWindow {
	return &NonceWindow{states: make(map[uint32]*nonceState)}
}

func (w *NonceWindow) Accept(connID, nonce uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	s, ok := w.states[connID]
	if !ok {
		w.states[connID] = &nonceState{maxNonce: nonce, seenMask: 1, initialized: true}
		return true
	}
	if !s.initialized {
		s.maxNonce = nonce
		s.seenMask = 1
		s.initialized = true
		return true
	}

	if nonce > s.maxNonce {
		shift := nonce - s.maxNonce
		if shift >= nonceWindowBits {
			s.seenMask = 1
		} else {
			s.seenMask = (s.seenMask << shift) | 1
		}
		s.maxNonce = nonce
		return true
	}

	delta := s.maxNonce - nonce
	if delta >= nonceWindowBits {
		return false
	}
	bit := uint64(1) << delta
	if (s.seenMask & bit) != 0 {
		return false
	}
	s.seenMask |= bit
	return true
}

func (w *NonceWindow) Remove(connID uint32) {
	w.mu.Lock()
	delete(w.states, connID)
	w.mu.Unlock()
}
