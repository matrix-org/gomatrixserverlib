package gomatrixserverlib

import (
	"context"
	"fmt"

	"golang.org/x/crypto/ed25519"
)

func (e *Event) VerifyEventSignatures(keyRing *KeyRing) error {
	// We need to check these keys.
	needed := map[ServerName]struct{}{}

	// The sender should have signed the event in all cases.
	_, serverName, err := SplitID('@', e.Sender())
	if err != nil {
		return fmt.Errorf("failed to split sender: %w", err)
	}
	needed[serverName] = struct{}{}

	// In room versions 1 and 2, we should also check that the server
	// that created the event is included too. This is probably the
	// same as the sender.
	if format, err := e.roomVersion.EventIDFormat(); err != nil {
		return fmt.Errorf("failed to get event ID format: %w", err)
	} else if format == EventIDFormatV1 {
		_, serverName, err = SplitID('$', e.EventID())
		if err != nil {
			return fmt.Errorf("failed to split event ID: %w", err)
		}
		needed[serverName] = struct{}{}
	}

	// Special checks for membership events.
	if e.Type() == MRoomMember {
		membership, err := e.Membership()
		if err != nil {
			return fmt.Errorf("failed to get membership of membership event: %w", err)
		}

		// For invites, the invited server should have signed the event.
		if membership == Invite {
			_, serverName, err = SplitID('@', *e.StateKey())
			if err != nil {
				return fmt.Errorf("failed to split state key: %w", err)
			}
			needed[serverName] = struct{}{}
		}

		// For restricted join rules, the authorising server should have signed.
		/*
			if restricted, err := e.roomVersion.AllowRestrictedJoinsInEventAuth(); err != nil {
				return fmt.Errorf("failed to check if restricted joins allowed: %w", err)
			} else if restricted && membership == Join {
				if v := gjson.GetBytes(e.Content(), "join_authorised_via_users_server"); v.Exists() {
					_, serverName, err = SplitID('@', v.String())
					if err != nil {
						return fmt.Errorf("failed to split authorised server: %w", err)
					}
					needed[serverName] = false
				}
			}
		*/
	}

	// Now check the signatures.
	requests := map[PublicKeyLookupRequest]Timestamp{}
	for serverName, byServerName := range e.Signatures {
		if _, ok := needed[serverName]; !ok {
			continue
		}
		for keyID := range byServerName {
			requests[PublicKeyLookupRequest{serverName, keyID}] = e.OriginServerTS()
		}
	}
	res, err := keyRing.KeyDatabase.FetchKeys(context.Background(), requests)
	if err != nil {
		return fmt.Errorf("failed to get signing keys: %w", err)
	}
	for req, res := range res {
		if err := e.Verify(string(req.ServerName), req.KeyID, ed25519.PublicKey(res.Key)); err != nil {
			return fmt.Errorf("signature validation for key ID %q for server %q failed: %w", req.KeyID, req.ServerName, err)
		}
	}

	return nil
}
