package server

import (
	"sync"
	"time"
)

const (
	unlockFailureLimit  = 5
	unlockFailureWindow = 5 * time.Minute
)

type unlockLimiter struct {
	mu       sync.Mutex
	failures map[string]unlockFailure
	now      func() time.Time
}

type unlockFailure struct {
	count int
	first time.Time
}

func newUnlockLimiter() *unlockLimiter {
	return &unlockLimiter{
		failures: make(map[string]unlockFailure),
		now:      time.Now,
	}
}

func (l *unlockLimiter) allow(key string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	failure, ok := l.failures[key]
	if !ok {
		return true
	}
	if l.now().Sub(failure.first) > unlockFailureWindow {
		delete(l.failures, key)
		return true
	}
	return failure.count < unlockFailureLimit
}

func (l *unlockLimiter) recordFailure(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	failure, ok := l.failures[key]
	if !ok || now.Sub(failure.first) > unlockFailureWindow {
		l.failures[key] = unlockFailure{count: 1, first: now}
		return
	}
	failure.count++
	l.failures[key] = failure
}

func (l *unlockLimiter) reset(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.failures, key)
	l.mu.Unlock()
}
