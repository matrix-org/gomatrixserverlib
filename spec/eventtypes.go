package spec

const (
	// Join is the string constant "join"
	Join = "join"
	// Ban is the string constant "ban"
	Ban = "ban"
	// Leave is the string constant "leave"
	Leave = "leave"
	// Invite is the string constant "invite"
	Invite = "invite"
	// Knock is the string constant "knock"
	Knock = "knock"
	// Restricted is the string constant "restricted"
	Restricted = "restricted"
	// NOTSPEC: Restricted is the string constant "knock_restricted" (MSC3787)
	// REVIEW: the MSC is merged though... so is this specced? Idk.
	KnockRestricted = "knock_restricted"
	// NOTSPEC: Peek is the string constant "peek" (MSC2753, used as the label in the sync block)
	Peek = "peek"
	// Public is the string constant "public"
	Public = "public"
	// WorldReadable is the string constant "world_readable"
	WorldReadable = "world_readable"
	// Room creation preset enum used to create private rooms
	PresetPrivateChat = "private_chat"
	// Room creation preset enum used to create trusted private rooms
	PresetTrustedPrivateChat = "trusted_private_chat"
	// Room creation preset enum used to create public rooms
	PresetPublicChat = "public_chat"
	// MRoomCreate https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-create
	MRoomCreate = "m.room.create"
	// MRoomJoinRules https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-join-rules
	MRoomJoinRules = "m.room.join_rules"
	// MRoomPowerLevels https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-power-levels
	MRoomPowerLevels = "m.room.power_levels"
	// MRoomName https://matrix.org/docs/spec/client_server/r0.6.0#m-room-name
	MRoomName = "m.room.name"
	// MRoomTopic https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-topic
	MRoomTopic = "m.room.topic"
	// MRoomAvatar https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-avatar
	MRoomAvatar = "m.room.avatar"
	// MRoomMember https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-member
	MRoomMember = "m.room.member"
	// MRoomThirdPartyInvite https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-third-party-invite
	MRoomThirdPartyInvite = "m.room.third_party_invite"
	// MRoomAliases https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-aliases
	MRoomAliases = "m.room.aliases"
	// MRoomCanonicalAlias https://matrix.org/docs/spec/client_server/r0.6.0#m-room-canonical-alias
	MRoomCanonicalAlias = "m.room.canonical_alias"
	// MRoomHistoryVisibility https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-history-visibility
	MRoomHistoryVisibility = "m.room.history_visibility"
	// MRoomGuestAccess https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-guest-access
	MRoomGuestAccess = "m.room.guest_access"
	// MRoomEncryption https://matrix.org/docs/spec/client_server/r0.2.0.html#m-room-encryption
	MRoomEncryption = "m.room.encryption"
	// MRoomRedaction https://matrix.org/docs/spec/client_server/r0.2.0.html#id21
	MRoomRedaction = "m.room.redaction"
	// MTyping https://matrix.org/docs/spec/client_server/r0.3.0.html#m-typing
	MTyping = "m.typing"
	// MDirectToDevice https://matrix.org/docs/spec/server_server/r0.1.3#send-to-device-messaging
	MDirectToDevice = "m.direct_to_device"
	// MDeviceListUpdate https://matrix.org/docs/spec/server_server/latest#m-device-list-update-schema
	MDeviceListUpdate = "m.device_list_update"
	// MReceipt https://matrix.org/docs/spec/server_server/r0.1.4#receipts
	MReceipt = "m.receipt"
	// MPresence https://matrix.org/docs/spec/server_server/latest#m-presence-schema
	MPresence = "m.presence"
	// MRoomMembership https://github.com/matrix-org/matrix-doc/blob/clokep/restricted-rooms/proposals/3083-restricted-rooms.md
	MRoomMembership = "m.room_membership"
	// MSpaceChild https://spec.matrix.org/v1.7/client-server-api/#mspacechild-relationship
	MSpaceChild = "m.space.child"
	// MSpaceParent https://spec.matrix.org/v1.7/client-server-api/#mspaceparent-relationships
	MSpaceParent = "m.space.parent"
)
