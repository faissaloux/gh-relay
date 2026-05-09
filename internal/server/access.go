package server

import (
	"sync"
	"time"
)

const (
	unlockFailureLimit  = 5
	unlockGlobalLimit   = 25
	unlockFailureWindow = 5 * time.Minute
)

type unlockLimiter struct {
	mu       sync.Mutex
	failures map[string]unlockFailure
	global   unlockFailure
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

func (l *unlockLimiter) blocked(key string) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.pruneLocked(now)
	return l.failures[key].count >= unlockFailureLimit || l.global.count >= unlockGlobalLimit
}

func (l *unlockLimiter) recordFailure(key string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.pruneLocked(now)
	if l.failures[key].count >= unlockFailureLimit || l.global.count >= unlockGlobalLimit {
		return false
	}

	keyFailure := l.failures[key]
	if keyFailure.first.IsZero() {
		keyFailure.first = now
	}
	keyFailure.count++
	l.failures[key] = keyFailure

	if l.global.first.IsZero() {
		l.global.first = now
	}
	l.global.count++
	return true
}

func (l *unlockLimiter) reset(key string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	delete(l.failures, key)
	l.mu.Unlock()
}

func (l *unlockLimiter) pruneLocked(now time.Time) {
	for key, failure := range l.failures {
		if now.Sub(failure.first) > unlockFailureWindow {
			delete(l.failures, key)
		}
	}
	if !l.global.first.IsZero() && now.Sub(l.global.first) > unlockFailureWindow {
		l.global = unlockFailure{}
	}
}
