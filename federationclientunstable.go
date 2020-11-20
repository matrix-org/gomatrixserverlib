package gomatrixserverlib

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

type UnstableFederationClient struct {
	*FederationClient
}

// Peek starts a peek on a remote server
func (ac *UnstableFederationClient) Peek(
	ctx context.Context, s ServerName, roomID, peekID string,
	roomVersions []RoomVersion,
) (res RespPeek, err error) {
	versionQueryString := ""
	if len(roomVersions) > 0 {
		var vqs []string
		for _, v := range roomVersions {
			vqs = append(vqs, fmt.Sprintf("ver=%s", url.QueryEscape(string(v))))
		}
		versionQueryString = "?" + strings.Join(vqs, "&")
	}
	path := federationPathPrefixV1 + "/peek/" +
		url.PathEscape(roomID) + "/" +
		url.PathEscape(peekID) + versionQueryString
	req := NewFederationRequest("PUT", s, path)
	var empty struct{}
	if err = req.SetContent(empty); err != nil {
		return
	}
	err = ac.doRequest(ctx, req, &res)
	return
}
