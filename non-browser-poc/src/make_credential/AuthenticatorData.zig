//! The authenticator data structure encodes contextual bindings made by the
//! authenticator. These bindings are controlled by the authenticator itself,
//! and derive their trust from the WebAuthn Relying Party's assessment of
//! the security properties of the authenticator.
//!
//! The authenticator data structure is a byte array of 37 bytes or more

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("keylib");

/// SHA-256 hash of the RP ID the credential is scoped to
rpIdHash: [32]u8,
/// Flags providing additional context to the given data
flags: packed struct(u8) {
    /// User Present (UP) result.
    /// - 1 means the user is present.
    /// - 0 means the user is not present.
    up: u1,
    /// Reserved for future use.
    rfu1: u1,
    /// User Verified (UV) result.
    /// - 1 means the user is verified.
    /// - 0 means the user is not verified.
    uv: u1,
    /// Reserved for future use.
    rfu2: u3,
    /// Attested credential data includet (AT).
    /// Indicates whether the authenticator added attested
    /// credential data.
    at: u1,
    /// Extension data included (ED).
    /// Indicates if the authenticator data has extensions.
    ed: u1,
},
/// Signature counter, 32-bit unsigned big-endian integer
signCount: u32,
/// Attested credential data
///
/// One could say this is the most important chunk of data because it contains
/// the credential (public key + cred_id) to be stored by the RP
attestedCredentialData: ?fido.common.AttestedCredentialData = null,
extensions: ?fido.ctap.extensions.Extensions = null,

/// Encode the given AuthenticatorData as byte array
pub fn encode(self: *const @This(), out: anytype) !void {
    try out.writeAll(self.rpIdHash[0..]);
    try out.writeByte(@as(u8, @bitCast(self.flags)));

    // counter is encoded in big-endian format
    try out.writeByte(@as(u8, @intCast((self.signCount >> 24) & 0xff)));
    try out.writeByte(@as(u8, @intCast((self.signCount >> 16) & 0xff)));
    try out.writeByte(@as(u8, @intCast((self.signCount >> 8) & 0xff)));
    try out.writeByte(@as(u8, @intCast(self.signCount & 0xff)));

    if (self.attestedCredentialData) |acd| {
        try acd.encode(out);
    }
}
