/*
 * MIT License
 *
 * Copyright (c) 2020 Sebastian Werner
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
	"testing"
	"time"
)

func TestContext(t *testing.T) {

	ctx := NewContext("test")

	ctx.NewIntOption("ival", 10)
	if ctx.Int("ival", 0) != 10 {
		t.Fail()
	}
	if ctx.Int("missing", 1112) != 1112 {
		t.Fail()
	}

	ctx.NewStingOption("sval", "hello")
	if ctx.String("sval", "") != "hello" {
		t.Fail()
	}
	if ctx.String("missing", "miss") != "miss" {
		t.Fail()
	}

	ctx.NewDurationOption("dval", time.Microsecond)
	if ctx.Duration("dval", time.Minute) != time.Microsecond {
		t.Fail()
	}

	ctx.NewBoolOption("bval", true)
	if !ctx.Bool("bval") {
		t.Fail()
	}
	slice := []string{"a", "b"}
	ctx.NewSliceOption("slice", slice)
	got := ctx.Slice("slice")
	if len(slice) != len(got) {
		t.Fail()
	}
	for i, s := range slice {
		if got[i] != s {
			t.Fail()
		}
	}

}
