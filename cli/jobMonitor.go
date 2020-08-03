// MIT License
//
// Copyright (c) 2020 Sebastian Werner
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

package cli

import (
	pb "github.com/schollz/progressbar/v3"
	"strings"
)

type ConsoleMonitor struct {
	bar     *pb.ProgressBar
	_new bool
}


func NewConsoleMonitor() *ConsoleMonitor {
	return &ConsoleMonitor{
		bar:     pb.NewOptions(1, pb.OptionShowIts(), pb.OptionSetRenderBlankState(true), pb.OptionFullWidth(), pb.OptionShowCount()),
		_new:    true,
	}
}

func (cm *ConsoleMonitor) Setup() {
	_ = cm.bar.Add(0)
}

func (cm *ConsoleMonitor)  Expand(delta int) {
	if cm._new {
		cm._new = false
	} else {
		cm.bar.ChangeMax(cm.bar.GetMax() + delta)
	}
	_ = cm.bar.Add(0)
}

func (cm *ConsoleMonitor) Advance(delta int) {
	_ = cm.bar.Add(delta)
}

func (cm *ConsoleMonitor) Render(){
	_ = cm.bar.Add(0)
	_ = cm.bar.RenderBlank()
}

func (cm *ConsoleMonitor) Finish() {
	_ = cm.bar.Finish()
}
func (cm *ConsoleMonitor) Info(text string) {
	info := strings.TrimSpace(text)
	cm.bar.Describe(info[:min(16, len(info))])
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}