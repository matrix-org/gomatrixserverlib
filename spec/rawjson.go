package spec

// TODO: Remove. Since Go 1.8 this has been fixed.
// RawJSON is a reimplementation of json.RawMessage that supports being used as a value type
//
// For example:
//
//	jsonBytes, _ := json.Marshal(struct{
//		RawMessage json.RawMessage
//		RawJSON RawJSON
//	}{
//		json.RawMessage(`"Hello"`),
//		RawJSON(`"World"`),
//	})
//
// Results in:
//
//	{"RawMessage":"IkhlbGxvIg==","RawJSON":"World"}
//
// See https://play.golang.org/p/FzhKIJP8-I for a full example.
type RawJSON []byte

// MarshalJSON implements the json.Marshaller interface using a value receiver.
// This means that RawJSON used as an embedded value will still encode correctly.
func (r RawJSON) MarshalJSON() ([]byte, error) {
	return []byte(r), nil
}

// UnmarshalJSON implements the json.Unmarshaller interface using a pointer receiver.
func (r *RawJSON) UnmarshalJSON(data []byte) error {
	*r = RawJSON(data)
	return nil
}
