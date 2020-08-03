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

package platforms


type OpenWhiskMessage struct {
	Value InitMessage `json:"value"`
}

type InitMessage struct {
	Name   string            `json:"name"`
	Main   string            `json:"main"`
	Code   string            `json:"code"`
	Binary bool              `json:"binary"`
	Env    map[string]string `json:"env"`
}

type RunMessage struct {
	Input         interface{} `json:"value"`
	Namespace     string                      `json:"namespace"`
	Name          string                      `json:"action_name"`
	Key           string                      `json:"api_key"`
	ActivationID  string                      `json:"activation_id"`
	TransactionID string                      `json:"transaction_id"`
}