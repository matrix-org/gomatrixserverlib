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

	"github.com/matrix-org/gomatrixserverlib/spec"
)

// A stateResV2ConflictedPowerLevel is used to sort the events by effective
// power level, origin server TS and the lexicographical comparison of event
// IDs. It is a bit of an optimisation to use this - by working out the
// effective power level etc ahead of time, we use less CPU cycles during the
// sort.
type stateResV2ConflictedPowerLevel struct {
	powerLevel     int64
	originServerTS spec.Timestamp
	eventID        string
	event          PDU
}

// A stateResV2ConflictedPowerLevelHeap is used to sort the events using
// sort.Sort or by using the heap functions for further optimisation. Sorting
// ensures that the results are deterministic.
type stateResV2ConflictedPowerLevelHeap []*stateResV2ConflictedPowerLevel

// Less implements sort.Interface
func sortStateResV2ConflictedPowerLevelHeap(a, b *stateResV2ConflictedPowerLevel) int {
	// Try to tiebreak on the effective power level
	if a.powerLevel > b.powerLevel {
		return -1
	}
	if a.powerLevel < b.powerLevel {
		return 1
	}
	// If we've reached here then s[i].powerLevel == s[j].powerLevel
	// so instead try to tiebreak on origin server TS
	if a.originServerTS < b.originServerTS {
		return -1
	}
	if a.originServerTS > b.originServerTS {
		return 1
	}
	// If we've reached here then s[i].originServerTS == s[j].originServerTS
	// so instead try to tiebreak on a lexicographical comparison of the event ID
	return strings.Compare(a.eventID[:], b.eventID[:])
}

// Push implements heap.Interface
func (s *stateResV2ConflictedPowerLevelHeap) Push(x *stateResV2ConflictedPowerLevel) {
	*s = append(*s, x)
}

// Pop implements heap.Interface
func (s *stateResV2ConflictedPowerLevelHeap) Pop() *stateResV2ConflictedPowerLevel {
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
	originServerTS   spec.Timestamp
	eventID          string
	event            PDU
}

// A stateResV2ConflictedOtherHeap is used to sort the events using
// sort.Sort or by using the heap functions for further optimisation. Sorting
// ensures that the results are deterministic.
type stateResV2ConflictedOtherHeap []*stateResV2ConflictedOther

func sortStateResV2ConflictedOtherHeap(a, b *stateResV2ConflictedOther) int {
	// Try to tiebreak on the mainline position
	if a.mainlinePosition < b.mainlinePosition {
		return -1
	}
	if a.mainlinePosition > b.mainlinePosition {
		return 1
	}
	// If we've reached here then s[i].mainlinePosition == s[j].mainlinePosition
	// so instead try to tiebreak on step count
	if a.mainlineSteps < b.mainlineSteps {
		return -1
	}
	if a.mainlineSteps > b.mainlineSteps {
		return 1
	}
	// If we've reached here then s[i].mainlineSteps == s[j].mainlineSteps
	// so instead try to tiebreak on origin server TS
	if a.originServerTS < b.originServerTS {
		return -1
	}
	if a.originServerTS > b.originServerTS {
		return 1
	}
	// If we've reached here then s[i].originServerTS == s[j].originServerTS
	// so instead try to tiebreak on a lexicographical comparison of the event ID
	return strings.Compare(a.eventID, b.eventID)
}

// Push implements heap.Interface
func (s *stateResV2ConflictedOtherHeap) Push(x *stateResV2ConflictedOther) {
	*s = append(*s, x)
}

// Pop implements heap.Interface
func (s *stateResV2ConflictedOtherHeap) Pop() *stateResV2ConflictedOther {
	old := *s
	n := len(old)
	x := old[n-1]
	*s = old[:n-1]
	return x
}
