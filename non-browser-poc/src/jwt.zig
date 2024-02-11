//! JSON Web Token (JWT) for OpenID
//!
//! JSON Web Token (JWT) is a compact, URL-safe means of representing
//! claims to be transferred between two parties.  The claims in a JWT
//! are encoded as a JSON object that is used as the payload of a JSON
//! Web Signature (JWS) structure or as the plaintext of a JSON Web
//! Encryption (JWE) structure, enabling the claims to be digitally
//! signed or integrity protected with a Message Authentication Code
//! (MAC) and/or encrypted ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519.html)).

const std = @import("std");
const Allocator = std.mem.Allocator;
const ES256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Base64Encoder = std.base64.url_safe.Encoder;

/// The header encodes that the object is a JWT (typ)
/// and specifies the type of JWT based on alg.
///
/// For JWS the ClaimSet is signed or MACed, and for JWEs
/// the ClaimSet is encrypted. OpenID uses digital signatures.
pub const Header = struct {
    typ: []const u8,
    alg: []const u8,
};

/// The claims of a OpenID JWT.
pub const ClaimSet = struct {
    /// Issuer claim: identifies the principal that issued the JWT.
    iss: []const u8,
    /// Subject claim: identifies the principal that is the subject of the JWT.
    sub: []const u8,
    /// The time the statement was issued in seconds form 1970-01-01T0:0:0Z (epoch).
    iat: i64,
    /// Expiration time after which the statement MUST NOT be accepted (epoch).
    exp: i64,
    /// A set of public signing keys.
    jwks: struct {
        keys: []const jwk.Key,
    },
    /// An array of strings representing the Entity Identifiers of Intermediate Entities or Trust Anchors.
    ///
    /// * REQUIRED in the Entity Configurations of the Entities that have at least one Superior above them.
    /// * MUST NOT be present in the Entity Configurations of Trust Anchors with no Superiors.
    /// * MUST NOT be present in Subordinate Statements.
    authority_hints: ?[]const []const u8 = null,
    /// Object with protocol-specific claims that represent the Entity's Types within its federations
    /// and metadata for those Entity Types
    metadata: ?Metadata = null,
};

pub const Metadata = struct {
    openid_provider: ?struct {
        /// Array specifying the federation types supported.
        ///
        /// * "automatic"
        /// * "explicit"
        client_registration_types_supported: []const []const u8,
        /// URL of the OP's federation-specific Dynamic Client Registration Endpoint.
        federation_registration_endpoint: ?[]const u8 = null,
        issuer: ?[]const u8 = null,
        signed_jwks_uri: ?[]const u8 = null,
        authorization_endpoint: ?[]const u8 = null,
        request_parameter_supported: ?bool = null,
        /// * "authorization_code"
        /// * "implicit"
        /// * "urn:ietf:params:oauth:grant-type:jwt-bearer"
        grant_types_supported: ?[]const []const u8 = null,
        /// * "ES256"
        id_token_signing_alg_values_supported: []const []const u8 = null,
        logo_uri: ?[]const u8 = null,
        op_policy_uri: ?[]const u8 = null,
        /// * "code"
        /// * "code id_token"
        /// * "token"
        response_types_supported: ?[]const []const u8 = null,
        /// * "pairwise"
        /// * "public"
        subject_types_supported: ?[]const []const u8 = null,
        token_endpoint: ?[]const u8 = null,
        /// * "client_secret_post"
        /// * "client_secret_basic"
        /// * "client_secret_jwt"
        /// * "private_key_jwt"
        token_endpoint_auth_methods_supported: ?[]const []const u8 = null,
    } = null,
    federation_entity: ?struct {
        contacts: ?[]const u8 = null,
        federation_fetch_endpoint: ?[]const u8 = null,
        homepage_uri: ?[]const u8 = null,
        organization_name: ?[]const u8 = null,
    } = null,
};

/// JSON Web Key (JWK)
pub const jwk = struct {
    pub const TKey = enum { Curve };

    pub const Alg = enum { ES256 };

    pub const Key = union(TKey) {
        Curve: struct {
            /// "ES256"
            alg: ?[]const u8 = null,
            /// "EC"
            kty: []const u8,
            /// "P-256"
            crv: []const u8,
            /// Base64 encoded x-coordinate
            x: []const u8,
            /// Base64 encoded y-coordinate
            y: []const u8,
            /// Base64 encoded private key
            d: ?[]const u8 = null,
            /// Key ID: the SHA-256 hash function of the key
            kid: ?[]const u8 = null,
        },

        pub fn new(alg: Alg, a: Allocator) !@This() {
            switch (alg) {
                .ES256 => {
                    const kp = try ES256.KeyPair.create(null);
                    const pub_key = kp.public_key.toUncompressedSec1();
                    var x = try a.alloc(u8, Base64Encoder.calcSize(32));
                    var y = try a.alloc(u8, Base64Encoder.calcSize(32));
                    var d_ = kp.secret_key.toBytes();
                    var d = try a.alloc(u8, Base64Encoder.calcSize(d_.len));

                    var k = @This(){
                        .Curve = .{
                            .alg = try a.dupe(u8, "ES256"),
                            .kty = try a.dupe(u8, "EC"),
                            .crv = try a.dupe(u8, "P-256"),
                            .x = Base64Encoder.encode(x, pub_key[1..33]),
                            .y = Base64Encoder.encode(y, pub_key[33..66]),
                            .d = Base64Encoder.encode(d, d_),
                        },
                    };

                    try k.calcKid(); // this will only fail if we run out of memory

                    return k;
                },
            }
        }

        pub fn deinit(self: *const @This(), a: Allocator) void {
            switch (self.*) {
                .Curve => |c| {
                    if (c.alg) |alg| {
                        a.free(alg);
                    }
                    a.free(c.kty);
                    a.free(c.crv);
                    a.free(c.x);
                    a.free(c.y);
                    if (c.d) |d| {
                        a.free(d);
                    }
                    if (c.kid) |kid| {
                        a.free(kid);
                    }
                },
            }
        }

        /// Calculate the [thumb-print](https://www.rfc-editor.org/rfc/rfc7638.html) of the key and set it as kid.
        pub fn calcKid(self: *@This(), a: Allocator) !void {
            var tp = std.ArrayList(u8).init(a);
            defer tp.deinit();

            switch (self.*) {
                .Curve => |*c| {
                    // Construct a JSON object containing only the required members
                    // of a JWK with no whitespace or line breaks in lexographical
                    // order.
                    try tp.appendSlice("{\"crv\":\"");
                    try tp.appendSlice(c.crv);
                    try tp.appendSlice("\",\"kty\":\"");
                    try tp.appendSlice(c.kty);
                    try tp.appendSlice("\",\"x\":\"");
                    try tp.appendSlice(c.x);
                    try tp.appendSlice("\",\"y\":\"");
                    try tp.appendSlice(c.y);
                    try tp.appendSlice("\"}");

                    // Hash the JSON object with SHA-256
                    var kid: [32]u8 = undefined;
                    std.crypto.hash.sha2.Sha256.hash(tp.items, &kid, .{});
                    var kid_ = try a.alloc(u8, Base64Encoder.calcSize(32));
                    c.kid = Base64Encoder.encode(kid_, &kid);
                },
            }
        }
    };
};

test "jwk calc kid #1" {
    const a = std.testing.allocator;

    var k = jwk.Key{
        .Curve = .{
            .kty = try a.dupe(u8, "EC"),
            .crv = try a.dupe(u8, "P-256"),
            .x = try a.dupe(u8, "X2S1dFE7zokQDST0bfHdlOWxOc8FC1l4_sG1Kwa4l4s"),
            .y = try a.dupe(u8, "812nU6OCKxgc2ZgSPt_dkXbYldG_smHJi4wXByDHc6g"),
        },
    };
    defer k.deinit(a);

    try k.calcKid(a);

    try std.testing.expectEqualStrings("-kErIK8gkYwo7XcKkcIA3lnUa4kwGctx2B5FQPu1pBw=", k.Curve.kid.?);
}
