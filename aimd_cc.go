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
	log "github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	"time"
)

type AIMDLimiter struct {
	*rateBucketLimiter
	*queryRateLimiter
	A       float64
	B       float64
	Thr     uint64
	MaxRate int
	ccw     *atomic.Float64

	slowStart *atomic.Uint32
	startTime time.Time
}

func NewAMIDLimiter(thr uint64, A, B float64, maxRPS int, clock LimiterClock) *AIMDLimiter {

	if A <= 0 {
		panic("A must be > 0")
	}

	if B <= 0 || B >= 1 {
		panic("B must be between 0 and 1")
	}

	a := &AIMDLimiter{
		A:         A,
		B:         B,
		Thr:       thr,
		MaxRate:   maxRPS,
		ccw:       atomic.NewFloat64(2),
		slowStart: atomic.NewUint32(1),
		startTime: clock.Now(),
	}
	a.rateBucketLimiter = newRateBucketLimiter(clock, maxRPS, a.update)
	a.queryRateLimiter = newQueryLimiter(maxRPS)

	return a
}
func (a *AIMDLimiter) Setup(ctx context.Context) {
	a.rateBucketLimiter.Setup(ctx)
	log.Debugf("t,tr,inflight,mLat\n")
}

func (a *AIMDLimiter) update(t time.Time) float64 {
	ccw := a.computeCCW()
	if ccw > float64(a.MaxRate) {
		ccw = float64(a.MaxRate)
		a.ccw.Store(ccw)
	}

	a.ccw.Store(ccw)

	duration := a.Clock.Now().Sub(a.startTime).Seconds()
	inflight := int64(a.closedCount.Load()) - int64(a.openCount.Load())
	log.Debugf("%.0f,%02.2f,%d,%5s\n", duration, ccw, inflight, a.meanRSP.Load())
	return ccw
}

func (a *AIMDLimiter) computeCCW() float64 {
	flight := int64(a.openCount.Load()) - int64(a.closedCount.Load())

	isConsetion := uint64(flight) > a.Thr

	load := a.slowStart.Load()
	if load < 4 {
		if isConsetion {
			//back to slow start
			if load > 0 {
				a.slowStart.Dec()
			}
			return float64(load)
		} else {
			//increase start window!
			acks := a.closedCount.Load()
			if acks > uint64(load*load) {
				inc := a.slowStart.Inc()
				return float64(inc * inc)
			}
		}
	} else if isConsetion {
		return a.ccw.Load() * a.B
	}

	return a.ccw.Load() + a.A

}
