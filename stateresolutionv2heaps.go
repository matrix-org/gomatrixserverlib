package gomatrixserverlib

import "strings"

// A conflictedPowerLevelEventV2 is used to sort the events in a block by ascending depth
// and descending sha1 of event ID. It is a bit of an optimisation to use this -
// by working out the effective power level etc ahead of time, we use less CPU
// cycles during the sort.
type conflictedPowerLevelEventV2 struct {
	powerLevel     int
	originServerTS int64
	eventID        string
	event          Event
}

// A conflictedPowerLevelEventV2Heap is used to sort the events using sort.Sort. We do
// this before processing the initial set of events with no incoming auth
// dependencies as it should help us get a deterministic result.
type conflictedPowerLevelEventV2Heap []conflictedPowerLevelEventV2

func (s conflictedPowerLevelEventV2Heap) Len() int {
	return len(s)
}

func (s conflictedPowerLevelEventV2Heap) Less(i, j int) bool {
	if s[i].powerLevel > s[j].powerLevel {
		return true
	}
	if s[i].originServerTS < s[j].originServerTS {
		return true
	}
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) < 0
}

func (s conflictedPowerLevelEventV2Heap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (pq *conflictedPowerLevelEventV2Heap) Push(x interface{}) {
	*pq = append(*pq, x.(conflictedPowerLevelEventV2))
}

func (pq *conflictedPowerLevelEventV2Heap) Pop() interface{} {
	old := *pq
	x := old[0]
	*pq = old[1:]
	return x
}

// A conflictedPowerLevelEventV2 is used to sort the events in a block by ascending depth
// and descending sha1 of event ID. It is a bit of an optimisation to use this -
// by working out the effective power level etc ahead of time, we use less CPU
// cycles during the sort.
type conflictedOtherEventV2 struct {
	mainlinePosition int
	originServerTS   int64
	eventID          string
	event            Event
}

// A conflictedPowerLevelEventV2Heap is used to sort the events using sort.Sort. We do
// this before processing the initial set of events with no incoming auth
// dependencies as it should help us get a deterministic result.
type conflictedOtherEventV2Heap []conflictedOtherEventV2

func (s conflictedOtherEventV2Heap) Len() int {
	return len(s)
}

func (s conflictedOtherEventV2Heap) Less(i, j int) bool {
	if s[i].mainlinePosition > s[j].mainlinePosition {
		return true
	}
	if s[i].originServerTS < s[j].originServerTS {
		return true
	}
	return strings.Compare(s[i].eventID[:], s[j].eventID[:]) < 0
}

func (s conflictedOtherEventV2Heap) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (pq *conflictedOtherEventV2Heap) Push(x interface{}) {
	*pq = append(*pq, x.(conflictedOtherEventV2))
}

func (pq *conflictedOtherEventV2Heap) Pop() interface{} {
	old := *pq
	x := old[0]
	*pq = old[1:]
	return x
}
