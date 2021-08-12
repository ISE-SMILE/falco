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
	"go.uber.org/atomic"
	"golang.org/x/time/rate"
	"math"
	"time"
)

type LimiterClock interface {
	Tick() <-chan time.Time
	Now() time.Time
}

type TimerClock struct {
	ticker *time.Ticker
}

func DefaultClock() LimiterClock {
	return NewTimedClock(time.Second)
}

func NewTimedClock(d time.Duration) LimiterClock {
	return &TimerClock{
		ticker: time.NewTicker(d),
	}
}

func (t *TimerClock) Tick() <-chan time.Time {
	return t.ticker.C
}
func (t *TimerClock) Now() time.Time {
	return time.Now()
}

//The CongestionController takes care of managing the rate of invocations and api requests send to a platform
type CongestionController interface {
	//Setup is called once after creating the controller, do your initialization here
	Setup(ctx context.Context)
	//Query blocks until a client can query again. Should be used for poll-based execution strategies
	Query(ctx context.Context) (*time.Time, error)
	//Take blocks until the next event can occur (blocks until ctx is cancelled)
	Take(ctx context.Context) (*time.Time, error)
	//Signal must be used for feedback to the controller every time an event is finished or failed, thus a new event can be send.
	Signal(took *time.Time)
}

//queryRateLimiter implementes a fixed requests per Second limiter for API query requests
type queryRateLimiter struct {
	rate *rate.Limiter
}

func newQueryLimiter(requestPerSecond int) *queryRateLimiter {
	return &queryRateLimiter{
		rate: rate.NewLimiter(rate.Every(time.Duration(requestPerSecond)/time.Second), 20),
	}
}

func (q *queryRateLimiter) Query(ctx context.Context) (*time.Time, error) {
	err := q.rate.Wait(ctx)
	if err != nil {
		return nil, err
	}

	t := time.Now()
	return &t, nil
}

//general CongestionController that uses a token bucket with a fixed interval clock to allow for ne requests.
//The token distribution will average to the set update-rate over time but can fluctuate for multiple intervals
type rateBucketLimiter struct {
	Update func(t time.Time) float64
	Clock  LimiterClock

	ctx    context.Context
	tokens chan struct{}

	openCount   *atomic.Uint64
	closedCount *atomic.Uint64
	meanRSP     *atomic.Duration
}

func newRateBucketLimiter(clock LimiterClock, maxToken int,
	update func(t time.Time) float64) *rateBucketLimiter {
	if clock == nil {
		clock = NewTimedClock(time.Second)
	}
	return &rateBucketLimiter{
		Clock:  clock,
		Update: update,
		tokens: make(chan struct{}, maxToken),

		openCount:   atomic.NewUint64(0),
		closedCount: atomic.NewUint64(0),
		meanRSP:     atomic.NewDuration(time.Minute * 1),
	}
}

func (p *rateBucketLimiter) Setup(ctx context.Context) {
	p.ctx = ctx
	go p.tick()
}

func (p *rateBucketLimiter) tick() {
	ticker := p.Clock.Tick()
	var ctx context.Context
	var cancel context.CancelFunc
	for {
		select {
		case <-p.ctx.Done():
			if cancel != nil {
				cancel()
			}
			return
		case t := <-ticker:
			if cancel != nil {
				cancel()
			}
			ctx, cancel = context.WithCancel(p.ctx)

			target := int(math.Max(math.Ceil(p.Update(t)), float64(cap(p.tokens))))
			if target > 0 {
				go func(t int) {

					newTokens := t - len(p.tokens)
					for i := 0; i < newTokens; i++ {
						p.tokens <- struct{}{}
						//we want to stop any ongoing token generation
						select {
						case <-ctx.Done():
							return
						default:
						}
					}
				}(target)
			}

		}
	}

}

func (p *rateBucketLimiter) Take(ctx context.Context) (*time.Time, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("cancled")
	case <-p.tokens:
		tick := time.Now()
		p.openCount.Inc()
		return &tick, nil
	}
}

func (p *rateBucketLimiter) Signal(tick *time.Time) {
	if tick != nil {
		lat := time.Now().Sub(*tick)
		meanLat := (p.meanRSP.Load() + lat) / time.Duration(2)
		p.meanRSP.Store(meanLat)
	}

	p.closedCount.Inc()
}
