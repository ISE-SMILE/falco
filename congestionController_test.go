/*
 * MIT License
 *
 * Copyright (c) 2021 Sebastian Werner
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package falco

import (
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type WorkerSimulation func(ctx context.Context, limiter CongestionController, clock LimiterClock,
	start time.Time, req *atomic.Int64, args *atomic.Int64)

type baselineCC struct {
	*rateBucketLimiter
	*queryRateLimiter
	startTime time.Time
	fixedRate float64
}

func (b baselineCC) Setup(ctx context.Context) {
	b.rateBucketLimiter.Setup(ctx)
	log.Debugf("t,tr,inflight,mLat\n")
}

func (b *baselineCC) update(t time.Time) float64 {
	duration := t.Sub(b.startTime).Seconds()
	inflight := int64(b.closedCount.Load()) - int64(b.openCount.Load())
	log.Debugf("%.0f,%.f,%d,%5s\n", duration, b.fixedRate, inflight, b.meanRSP.Load())
	return b.fixedRate
}
func TestTokenBaseline(t *testing.T) {
	clock := NewTimedClock(1000 * time.Millisecond)

	fixedRate := 10.
	limiter := &baselineCC{
		startTime: clock.Now(),
		fixedRate: fixedRate,
	}
	limiter.rateBucketLimiter = newRateBucketLimiter(clock, int(fixedRate), limiter.update)
	limiter.queryRateLimiter = newQueryLimiter(int(fixedRate))

	sims := []struct {
		wl   WorkerSimulation
		name string
	}{
		{GreedySpeedup, "greedy"},
		{ServiceError, "no_acks"},
		{SlowStart, "slow"},
		{Elastic, "elastic"},
	}
	for _, sim := range sims {
		t.Run("baseline_"+sim.name, func(t *testing.T) {
			graph := test(t, "baseline_"+sim.name, 40, 8, limiter, clock, sim.wl)
			for k, v := range graph {
				assert.Less(t, float64(v), fixedRate*1.25,
					fmt.Sprintf("baseline exceeded fixedRate of %.f by %.f at time:%d", fixedRate, fixedRate-float64(v), k))
			}
		})
	}
}

func TestErrorCases(t *testing.T) {
	sims := []struct {
		wl   WorkerSimulation
		name string
	}{
		{GreedySpeedup, "greedy"},
		{ServiceError, "no_acks"},
		{SlowStart, "slow"},
		{Elastic, "elastic2"},
		{SlowStartElastic, "elastic"},
		{ElasticCongestion, "upto15"},
	}
	for _, sim := range sims {
		t.Run("pid_"+sim.name, func(t *testing.T) {
			clock := NewTimedClock(500 * time.Millisecond)
			limiter := NewPIDLimiter(1, 0.5, 0.5, 2, 60, 10, clock)
			name := fmt.Sprintf("pid_%s_%.2f_%.2f_%.2f_%.2f", sim.name, 1.0, 0.5, 0.5, 2.0)
			test(t, name, 40, 8, limiter, clock, sim.wl)
		})

		t.Run("amid_"+sim.name, func(t *testing.T) {
			clock := NewTimedClock(500 * time.Millisecond)
			limiter := NewAMIDLimiter(10, 1.5, 0.5, 60, clock)
			name := fmt.Sprintf("amid_%s_%.2f_%.2f_%d", sim.name, 1.5, 0.5, 10)
			test(t, name, 40, 8, limiter, clock, sim.wl)
		})
	}

}

func TestPIDLimiter(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	workloads := []struct {
		name string
		P    float64
		I    float64
		D    float64
		F    float64
		thr  int
		open int
		wl   WorkerSimulation
	}{
		{"slow", 1, 0.5, 0.5, 0.25, 8, 10, SlowStart},
		{"slow", 0.5, 0.5, 0.5, 1, 8, 10, SlowStart},

		{"elastic", 1, 0.5, 0.5, 0.25, 8, 10, SlowStartElastic},
		{"elastic", 0.5, 0.5, 0.5, 1, 8, 10, SlowStartElastic},

		{"elastic2", 1, 0.5, 0.5, 0.25, 8, 10, Elastic},
		{"elastic2", 0.5, 0.5, 0.5, 1, 8, 10, Elastic},

		{"upto15", 1, 0.5, 0.5, 0.25, 8, 10, ElasticCongestion},
		{"upto15", 0.5, 0.5, 0.5, 1, 8, 10, ElasticCongestion},
	}

	for _, wl := range workloads {
		t.Run("pid_"+wl.name, func(t *testing.T) {
			clock := NewTimedClock(500 * time.Millisecond)
			limiter := NewPIDLimiter(wl.P, wl.I, wl.D, wl.F, 60, wl.open, clock)
			name := fmt.Sprintf("pid_%s_%.2f_%.2f_%.2f_%.2f", wl.name, wl.P, wl.I, wl.D, wl.F)
			test(t, name, 40, wl.thr, limiter, clock, wl.wl)
		})
	}

}

func TestAMIDLimiter(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	workloads := []struct {
		name string
		A    float64
		B    float64
		Thr  uint64
		wl   WorkerSimulation
	}{

		{"slow", 2, 0.5, 10, SlowStart},
		{"slow", 2, 0.25, 10, SlowStart},
		{"slow", 2, 0.75, 10, SlowStart},

		{"elastic", 2, 0.5, 10, SlowStartElastic},
		{"elastic", 2, 0.25, 10, SlowStartElastic},
		{"elastic", 2, 0.75, 10, SlowStartElastic},

		{"elastic2", 2, 0.5, 10, Elastic},
		{"elastic2", 2, 0.25, 10, Elastic},
		{"elastic2", 2, 0.75, 10, Elastic},

		{"upto15", 2, 0.5, 10, ElasticCongestion},
		{"upto15", 2, 0.25, 10, ElasticCongestion},
		{"upto15", 2, 0.75, 10, ElasticCongestion},
	}

	for _, wl := range workloads {
		t.Run("amid_"+wl.name, func(t *testing.T) {
			clock := NewTimedClock(500 * time.Millisecond)
			limiter := NewAMIDLimiter(wl.Thr, wl.A, wl.B, 60, clock)
			name := fmt.Sprintf("amid_%s_%.2f_%.2f_%d", wl.name, wl.A, wl.B, wl.Thr)
			test(t, name, 40, 8, limiter, clock, wl.wl)
		})
	}

}

func GreedySpeedup(ctx context.Context, limiter CongestionController, clock LimiterClock,
	start time.Time, req *atomic.Int64, args *atomic.Int64) {
	for {
		t, err := limiter.Take(ctx)
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:

		}
		start := int(clock.Now().Sub(start) / time.Second)
		var dur int
		if start*30 >= 1000 {
			dur = 30
		} else {
			dur = rand.Intn(1000 - start*30)
		}

		time.Sleep(time.Millisecond * time.Duration(dur))
		limiter.Signal(t)
		req.Inc()
	}
}

func SlowStart(ctx context.Context, limiter CongestionController, clock LimiterClock,
	start time.Time, req *atomic.Int64, args *atomic.Int64) {
	for {
		t, err := limiter.Take(ctx)
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:

		}
		trigger := clock.Now().Sub(start) - 15*time.Second
		if trigger < 0 {
			time.Sleep(5 * time.Second)
		} else {
			time.Sleep(500 * time.Millisecond)
		}
		limiter.Signal(t)
		req.Inc()
	}
}

func SlowStartElastic(ctx context.Context, limiter CongestionController, clock LimiterClock,
	start time.Time, req *atomic.Int64, args *atomic.Int64) {
	for {

		select {
		case <-ctx.Done():
			return
		default:

		}

		trigger := clock.Now().Sub(start) - 15*time.Second
		t, err := limiter.Take(ctx)
		if err != nil {
			return
		}
		if trigger < 0 {
			time.Sleep(5 * time.Second)
		} else {
			pressure := int(trigger/time.Second) + 1
			for i := 0; i < rand.Intn(pressure); i++ {
				go func() {
					t, err := limiter.Take(ctx)
					if err != nil {
						return
					}
					time.Sleep(250 * time.Millisecond)
					limiter.Signal(t)
					req.Inc()
				}()
			}
		}
		limiter.Signal(t)
		req.Inc()
	}
}

func Elastic(ctx context.Context, limiter CongestionController, clock LimiterClock,
	start time.Time, req *atomic.Int64, args *atomic.Int64) {
	for {

		select {
		case <-ctx.Done():
			return
		default:

		}

		t, err := limiter.Take(ctx)
		if err != nil {
			return
		}
		if args.Load() == 0 || req.Load()%args.Load() == 0 {
			args.Inc()
			time.Sleep(1 * time.Second)
		} else {
			time.Sleep(100 * time.Millisecond)
		}

		limiter.Signal(t)
		req.Inc()

	}
}

func ElasticCongestion(ctx context.Context, limiter CongestionController, clock LimiterClock,
	start time.Time, req *atomic.Int64, args *atomic.Int64) {
	for {

		select {
		case <-ctx.Done():
			return
		default:

		}

		open := args.Inc()
		closed := req.Load()
		t, err := limiter.Take(ctx)
		if err != nil {
			return
		}

		//we have more than 15 inflight messages
		if open-closed > 5 {
			time.Sleep(1200 * time.Millisecond)
		} else {
			time.Sleep(time.Duration(rand.Int31n(7)*100) * time.Millisecond)
		}

		limiter.Signal(t)
		req.Inc()

	}
}

func ServiceError(ctx context.Context, limiter CongestionController, clock LimiterClock,
	start time.Time, req *atomic.Int64, args *atomic.Int64) {
	for {

		select {
		case <-ctx.Done():
			return
		default:

		}

		_, err := limiter.Take(ctx)
		if err != nil {
			return
		}
		req.Inc()
		time.Sleep(500 * time.Millisecond)
	}
}

func test(t *testing.T, name string, duration int, threads int, limiter CongestionController, clock LimiterClock, tester WorkerSimulation) map[int64]int64 {
	log.SetLevel(log.DebugLevel)

	_ = os.Mkdir(filepath.Join("plots", name), 0777)

	out, err := os.OpenFile(filepath.Join("plots", name, "pid.csv"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0664)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	log.SetOutput(out)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(duration))
	defer cancel()

	limiter.Setup(ctx)

	req := atomic.NewInt64(0)
	args := atomic.NewInt64(0)
	start := clock.Now()
	graph := make(map[int64]int64)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:

			}

			elapsed := int64(time.Now().Sub(start) / time.Second)

			var rps int64
			if elapsed == 0 {
				rps = 0
			} else {
				rps = req.Load() / elapsed
			}

			graph[elapsed] = rps

			time.Sleep(1 * time.Second)
		}
	}()
	for i := 0; i < threads; i++ {
		go tester(ctx, limiter, clock, start, req, args)
	}

	<-ctx.Done()
	//t.Log(req.Load())
	assert.True(t, req.Load() > 0)

	result, err := os.OpenFile(filepath.Join("plots", name, "result.csv"),
		os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0664)
	if err != nil {
		t.Fatal()
	}
	defer func() { _ = result.Close() }()

	_, _ = result.WriteString("t,rps\n")
	for i := 0; i < int(duration); i++ {
		if val, ok := graph[int64(i)]; ok {
			_, _ = result.WriteString(fmt.Sprintf("%d,%d\n ", i, val))
		}
	}

	return graph

}
