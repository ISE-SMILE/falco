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
	"math"
	"sync"
	"time"
)

//PIDLimiter implements a PID driven CongestionController that will use the PID algortithm to reach a target RPS
type PIDLimiter struct {
	*sync.Mutex
	*rateBucketLimiter
	*queryRateLimiter

	P float64
	I float64
	D float64
	F float64 //this factor influences how much the number of open requests should dampen the allowed rate per interval

	TargetRPS       int //the targeted requests per second for the PID algortihm
	MaxOpenRequests int //the maximum allowed number of open request. The difference of this with the current ongoing request * F will be added to the control signal)

	rate *atomic.Float64

	ctx context.Context

	signalTime time.Time

	lastCError float64
	cumError   float64
	errorRate  float64
	startTime  time.Time
}

func NewPIDLimiter(
	P, I, D, F float64,
	targetRPS, maxOpen int, clock LimiterClock) *PIDLimiter {
	if clock == nil {
		clock = NewTimedClock(time.Second)
	}

	p := &PIDLimiter{
		Mutex:           &sync.Mutex{},
		P:               P,
		I:               I,
		D:               D,
		F:               F,
		TargetRPS:       targetRPS,
		MaxOpenRequests: maxOpen,
		signalTime:      clock.Now(),
		startTime:       clock.Now(),
	}
	p.rateBucketLimiter = newRateBucketLimiter(clock, 2*targetRPS, p.updateRate)
	p.queryRateLimiter = newQueryLimiter(targetRPS)

	p.rate = atomic.NewFloat64(0)

	return p
}

func (p *PIDLimiter) Setup(ctx context.Context) {
	p.rateBucketLimiter.Setup(ctx)
	//used for plotting ;)
	log.Debugf("t,cr,tr,err,cumErr,inflight,mLat")
}

func (p *PIDLimiter) updateRate(signal time.Time) float64 {
	p.Lock()
	defer p.Unlock()

	//elapsed time time in seconds
	elapsedTime := float64(signal.Sub(p.startTime)) / float64(time.Second)
	if elapsedTime <= 0 {
		return p.rate.Load()
	}

	cumReq := float64(p.closedCount.Load())
	currentRate := cumReq / elapsedTime
	//number of in-flight requests (negative if more open than closed
	inflight := cumReq - float64(p.openCount.Load())
	rate := p.computePID(currentRate, inflight)
	log.Debugf("%02.2f,%02.2f,%02.2f,%02.2f,%02.2f,%02.2f,%5s\n",
		elapsedTime, currentRate, rate, p.lastCError, p.cumError, inflight, p.meanRSP.Load())
	if !math.IsNaN(rate) {
		p.rate.Store(rate)
		return rate
	} else {
		return p.rate.Load()
	}
}

func (p *PIDLimiter) computePID(inp float64, inflight float64) float64 {

	currentTime := p.Clock.Now()
	elapsedTime := float64(currentTime.Sub(p.signalTime)) / float64(time.Second)

	//delta of current input singal vs target rate
	cError := float64(p.TargetRPS) - inp
	//cumulative error of timer
	p.cumError += cError * elapsedTime
	//error rate
	p.errorRate = (cError - p.lastCError) / (elapsedTime + math.SmallestNonzeroFloat64)
	//this value will get larger the more open requests there are above max
	inflightError := float64(p.MaxOpenRequests) - inflight*-1

	//PID + inflight dampaning + runtmeError dampaning
	//R should be small, the higher F the more cautious the signal will increase
	signal := p.P*cError + p.I*p.cumError + p.D*p.errorRate

	//while we want to change the signal in portion to open requests above the threshold
	//we do not want to increase the signal if we have less open request than allowed
	if inflightError < 0 {
		signal -= p.F * inflightError
	}

	p.lastCError = cError      //remember current error
	p.signalTime = currentTime //remember current time

	return signal //have function return the PID output

}
