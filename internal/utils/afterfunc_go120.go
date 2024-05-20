//go:build !go1.21

package utils

import (
	"context"
	"sync"
)

func AfterFunc(ctx context.Context, f func()) (stop func() bool) {
	stopc := make(chan struct{}, 1)
	donec := make(chan struct{})
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				f()
			case <-stopc:
			}
			close(donec)
		}()
	} else {
		close(donec)
	}

	once := sync.Once{}
	return func() bool {
		stopped := false
		once.Do(func() {
			stopped = true
			select {
			case stopc <- struct{}{}:
			default:
			}
			<-donec
		})
		return stopped
	}
}
