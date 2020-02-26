package gomatrixserverlib

import (
	"strings"
)

// A stateResV2ConflictedPowerLevel is used to sort the events in a block by ascending depth
// and descending sha1 of event ID. It is a bit of an optimisation to use this -
// by working out the effective power level etc ahead of time, we use less CPU
// cycles during the sort.
type stateResV2ConflictedPowerLevel struct {
	powerLevel     int
	originServerTS int64
	eventID        string
	event          Event
}

// A stateResV2ConflictedPowerLevelHeap is used to sort the events using sort.Sort. We do
// this before processing the initial set of events with no incoming auth
// dependencies as it should help us get a deterministic result.
type stateResV2ConflictedPowerLevelHeap []stateResV2ConflictedPowerLevel

func (s stateResV2ConflictedPowerLevelHeap) Len() int {
	return len(s)
}

func (s stateResV2ConflictedPowerLevelHeap) Less(i, j int) bool {
	if s[i].powerLevel > s[j].powerLevel {
		return true
	}
	if s[i].powerLevel < s[j].powerLevel {
		return false
	}
	if s[i].originServerTS < s[j].originServerTS {
		return true
	}
	if s[i].originServerTS > s[j].originServerTS {
		return false
	}
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) < 0
}

func (s stateResV2ConflictedPowerLevelHeap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s *stateResV2ConflictedPowerLevelHeap) Push(x interface{}) {
	*s = append(*pq, x.(stateResV2ConflictedPowerLevel))
}

func (s *stateResV2ConflictedPowerLevelHeap) Pop() interface{} {
	old := *s
	x := old[0]
	*s = old[1:]
	return x
}

// A stateResV2ConflictedPowerLevel is used to sort the events in a block by ascending depth
// and descending sha1 of event ID. It is a bit of an optimisation to use this -
// by working out the effective power level etc ahead of time, we use less CPU
// cycles during the sort.
type stateResV2ConflictedOther struct {
	mainlinePosition int
	originServerTS   int64
	eventID          string
	event            Event
}

// A stateResV2ConflictedPowerLevelHeap is used to sort the events using sort.Sort. We do
// this before processing the initial set of events with no incoming auth
// dependencies as it should help us get a deterministic result.
type stateResV2ConflictedOtherHeap []stateResV2ConflictedOther

func (s stateResV2ConflictedOtherHeap) Len() int {
	return len(s)
}

func (s stateResV2ConflictedOtherHeap) Less(i, j int) bool {
	if s[i].mainlinePosition > s[j].mainlinePosition {
		return true
	}
	if s[i].mainlinePosition < s[j].mainlinePosition {
		return false
	}
	if s[i].originServerTS < s[j].originServerTS {
		return true
	}
	if s[i].originServerTS > s[j].originServerTS {
		return false
	}
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) > 0
}

func (s stateResV2ConflictedOtherHeap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s *stateResV2ConflictedOtherHeap) Push(x interface{}) {
	*s = append(*pq, x.(stateResV2ConflictedOther))
}

func (s *stateResV2ConflictedOtherHeap) Pop() interface{} {
	old := *s
	x := old[0]
	*s = old[1:]
	return x
}
