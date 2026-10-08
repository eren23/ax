// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lock_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/ax/internal/lock"
	"github.com/redis/go-redis/v9"
)

func TestMemoryLocker_SerializesSameResource(t *testing.T) {
	locker := lock.NewMemoryLocker()
	ctx := context.Background()

	var counter int64
	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := locker.Lock(ctx, "task", "default", "my-task")
			if err != nil {
				t.Errorf("unexpected lock error: %v", err)
				return
			}
			defer unlock()

			current := atomic.AddInt64(&counter, 1)
			time.Sleep(10 * time.Millisecond)
			if atomic.LoadInt64(&counter) != current {
				t.Errorf("race condition detected: counter changed while lock held")
			}
		}()
	}

	wg.Wait()
}

func TestMemoryLocker_ConcurrentDifferentResources(t *testing.T) {
	locker := lock.NewMemoryLocker()
	ctx := context.Background()

	unlock1, err := locker.Lock(ctx, "task", "default", "task-1")
	if err != nil {
		t.Fatalf("lock task-1: %v", err)
	}
	defer unlock1()

	// Different resource should acquire immediately
	start := time.Now()
	unlock2, err := locker.Lock(ctx, "task", "default", "task-2")
	if err != nil {
		t.Fatalf("lock task-2: %v", err)
	}
	defer unlock2()

	if time.Since(start) > 50*time.Millisecond {
		t.Errorf("different resource lock was blocked")
	}
}

func TestMemoryLocker_Timeout(t *testing.T) {
	locker := lock.NewMemoryLocker()
	ctx := context.Background()

	unlock1, err := locker.Lock(ctx, "task", "default", "task-1")
	if err != nil {
		t.Fatalf("lock task-1: %v", err)
	}
	defer unlock1()

	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()

	_, err = locker.Lock(timeoutCtx, "task", "default", "task-1")
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
}

// The Redis lease must outlive its TTL while the holder runs. Set
// AX_TEST_REDIS_ADDR (for example localhost:6379) to run it.
func TestRedisLocker_RenewsLeaseWhileHeld(t *testing.T) {
	addr := os.Getenv("AX_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("AX_TEST_REDIS_ADDR not set")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	defer client.Close()
	locker := lock.NewRedisLocker(client, lock.RedisLockerOptions{TTL: 300 * time.Millisecond, FallbackInterval: 20 * time.Millisecond})
	ctx := context.Background()
	name := fmt.Sprintf("renew-%d", time.Now().UnixNano())

	unlock, err := locker.Lock(ctx, "task", "default", name)
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	time.Sleep(1 * time.Second) // more than three TTLs

	waitCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if unlock2, err := locker.Lock(waitCtx, "task", "default", name); err == nil {
		unlock2()
		t.Fatal("a second holder got the lock after the TTL; the lease was not renewed")
	}

	unlock()
	unlock2, err := locker.Lock(ctx, "task", "default", name)
	if err != nil {
		t.Fatalf("Lock after unlock: %v", err)
	}
	unlock2()
	time.Sleep(500 * time.Millisecond) // the stopped renewal must not bring the key back
	if n, _ := client.Exists(ctx, lock.Key("task", "default", name)).Result(); n != 0 {
		t.Errorf("lock key still exists after unlock")
	}
}
