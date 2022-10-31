// Copyright 2020 The Matrix.org Foundation C.I.C.
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

package gomatrixserverlib

import (
	"strings"
)

// A stateResV2ConflictedPowerLevel is used to sort the events by effective
// power level, origin server TS and the lexicographical comparison of event
// IDs. It is a bit of an optimisation to use this - by working out the
// effective power level etc ahead of time, we use less CPU cycles during the
// sort.
type stateResV2ConflictedPowerLevel struct {
	powerLevel     int64
	originServerTS Timestamp
	eventID        string
	event          *Event
}

// A stateResV2ConflictedPowerLevelHeap is used to sort the events using
// sort.Sort or by using the heap functions for further optimisation. Sorting
// ensures that the results are deterministic.
type stateResV2ConflictedPowerLevelHeap []*stateResV2ConflictedPowerLevel

// Len implements sort.Interface
func (s stateResV2ConflictedPowerLevelHeap) Len() int {
	return len(s)
}

// Less implements sort.Interface
func (s stateResV2ConflictedPowerLevelHeap) Less(i, j int) bool {
	// Try to tiebreak on the effective power level
	if s[i].powerLevel > s[j].powerLevel {
		return true
	}
	if s[i].powerLevel < s[j].powerLevel {
		return false
	}
	// If we've reached here then s[i].powerLevel == s[j].powerLevel
	// so instead try to tiebreak on origin server TS
	if s[i].originServerTS < s[j].originServerTS {
		return false
	}
	if s[i].originServerTS > s[j].originServerTS {
		return true
	}
	// If we've reached here then s[i].originServerTS == s[j].originServerTS
	// so instead try to tiebreak on a lexicographical comparison of the event ID
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) > 0
}

// Swap implements sort.Interface
func (s stateResV2ConflictedPowerLevelHeap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Push implements heap.Interface
func (s *stateResV2ConflictedPowerLevelHeap) Push(x interface{}) {
	*s = append(*s, x.(*stateResV2ConflictedPowerLevel))
}

// Pop implements heap.Interface
func (s *stateResV2ConflictedPowerLevelHeap) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[:n-1]
	return x
}

// A stateResV2ConflictedOther is used to sort the events by power level
// mainline positions, origin server TS and the lexicographical comparison of
// event IDs. It is a bit of an optimisation to use this - by working out the
// effective power level etc ahead of time, we use less CPU cycles during the
// sort.
type stateResV2ConflictedOther struct {
	mainlinePosition int
	mainlineSteps    int
	originServerTS   Timestamp
	eventID          string
	event            *Event
}

// A stateResV2ConflictedOtherHeap is used to sort the events using
// sort.Sort or by using the heap functions for further optimisation. Sorting
// ensures that the results are deterministic.
type stateResV2ConflictedOtherHeap []*stateResV2ConflictedOther

// Len implements sort.Interface
func (s stateResV2ConflictedOtherHeap) Len() int {
	return len(s)
}

// Less implements sort.Interface
func (s stateResV2ConflictedOtherHeap) Less(i, j int) bool {
	// Try to tiebreak on the mainline position
	if s[i].mainlinePosition < s[j].mainlinePosition {
		return true
	}
	if s[i].mainlinePosition > s[j].mainlinePosition {
		return false
	}
	// If we've reached here then s[i].mainlinePosition == s[j].mainlinePosition
	// so instead try to tiebreak on step count
	if s[i].mainlineSteps < s[j].mainlineSteps {
		return true
	}
	if s[i].mainlineSteps > s[j].mainlineSteps {
		return false
	}
	// If we've reached here then s[i].mainlineSteps == s[j].mainlineSteps
	// so instead try to tiebreak on origin server TS
	if s[i].originServerTS < s[j].originServerTS {
		return true
	}
	if s[i].originServerTS > s[j].originServerTS {
		return false
	}
	// If we've reached here then s[i].originServerTS == s[j].originServerTS
	// so instead try to tiebreak on a lexicographical comparison of the event ID
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) < 0
}

// Swap implements sort.Interface
func (s stateResV2ConflictedOtherHeap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Push implements heap.Interface
func (s *stateResV2ConflictedOtherHeap) Push(x interface{}) {
	*s = append(*s, x.(*stateResV2ConflictedOther))
}

// Pop implements heap.Interface
func (s *stateResV2ConflictedOtherHeap) Pop() interface{} {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[:n-1]
	return x
}
