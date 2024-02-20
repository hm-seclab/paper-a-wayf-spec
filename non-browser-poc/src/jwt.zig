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
const Base64Encoder = std.base64.url_safe_no_pad.Encoder;
const Base64Decoder = std.base64.url_safe_no_pad.Decoder;

pub const JWS = struct {
    header: Header,
    payload: ClaimSet,
    data: []const u8,
    sig: []const u8,

    pub fn fromSlice(s: []const u8, a: Allocator) !@This() {
        var d1: usize = 0;
        while (d1 < s.len and s[d1] != '.') : (d1 += 1) {}
        if (d1 >= s.len) return error.Malformed;

        var d2: usize = d1 + 1;
        while (d2 < s.len and s[d2] != '.') : (d2 += 1) {}
        if (d2 >= s.len - 1) return error.Malformed;

        const hs = try Base64Decoder.calcSizeForSlice(s[0..d1]);
        var h = try a.alloc(u8, hs);
        defer a.free(h);
        try Base64Decoder.decode(h, s[0..d1]);

        const ps = try Base64Decoder.calcSizeForSlice(s[d1 + 1 .. d2]);
        var p = try a.alloc(u8, ps);
        defer a.free(p);
        try Base64Decoder.decode(p, s[d1 + 1 .. d2]);

        var self = @This(){
            .header = try std.json.parseFromSliceLeaky(Header, a, h, .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = true,
            }),
            .payload = try std.json.parseFromSliceLeaky(ClaimSet, a, p, .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = true,
            }),
            .data = try a.dupe(u8, s[0..d2]),
            .sig = try a.dupe(u8, s[d2 + 1 ..]),
        };

        return self;
    }

    pub fn deinit(self: *const @This(), a: Allocator) void {
        self.header.deinit(a);
        self.payload.deinit(a);
        a.free(self.data);
        a.free(self.sig);
    }
};

/// The header encodes that the object is a JWT (typ)
/// and specifies the type of JWT based on alg.
///
/// For JWS the ClaimSet is signed or MACed, and for JWEs
/// the ClaimSet is encrypted. OpenID uses digital signatures.
pub const Header = struct {
    typ: ?[]const u8 = null,
    alg: ?[]const u8 = null,
    kid: ?[]const u8 = null,

    pub fn deinit(self: *const @This(), a: Allocator) void {
        if (self.typ) |v| {
            a.free(v);
        }
        if (self.alg) |v| {
            a.free(v);
        }
        if (self.kid) |v| {
            a.free(v);
        }
    }
};

/// The claims of a OpenID JWT.
pub const ClaimSet = struct {
    /// Issuer claim: identifies the principal that issued the JWT.
    iss: []const u8 = "",
    /// Subject claim: identifies the principal that is the subject of the JWT.
    sub: []const u8 = "",
    /// The time the statement was issued in seconds form 1970-01-01T0:0:0Z (epoch).
    iat: i64 = 0,
    /// Expiration time after which the statement MUST NOT be accepted (epoch).
    exp: i64 = 0,
    /// A set of public signing keys.
    jwks: struct {
        keys: []const jwk.Key = &.{},
    },
    /// An array of strings representing the Entity Identifiers of Intermediate Entities or Trust Anchors.
    ///
    /// * REQUIRED in the Entity Configurations of the Entities that have at least one Superior above them.
    /// * MUST NOT be present in the Entity Configurations of Trust Anchors with no Superiors.
    /// * MUST NOT be present in Subordinate Statements.
    authority_hints: ?[]const []const u8 = null,
    // Object with protocol-specific claims that represent the Entity's Types within its federations
    // and metadata for those Entity Types
    //metadata: ?Metadata = null,
    /// List of statements...
    trust_chain: ?[]const []const u8 = null,

    pub fn deinit(self: *const @This(), a: Allocator) void {
        a.free(self.iss);
        a.free(self.sub);
        for (self.jwks.keys) |k| {
            k.deinit(a);
        }
        a.free(self.jwks.keys);
        if (self.authority_hints) |ah| {
            for (ah) |h| {
                a.free(h);
            }
            a.free(ah);
        }
        //if (self.metadata) |metadata| {
        //    metadata.deinit();
        //}
        if (self.trust_chain) |tc| {
            for (tc) |e| {
                a.free(e);
            }
            a.free(tc);
        }
    }
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
        id_token_signing_alg_values_supported: ?[]const []const u8 = null,
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
    pub const Alg = enum { ES256 };

    pub const Key = struct {
        /// "ES256"
        alg: ?[]const u8 = null,
        /// "EC"
        kty: []const u8,
        /// "P-256"
        crv: ?[]const u8 = null,
        /// Base64 encoded x-coordinate
        x: ?[]const u8 = null,
        /// Base64 encoded y-coordinate
        y: ?[]const u8 = null,
        /// Base64 encoded private key
        d: ?[]const u8 = null,
        /// Key ID: the SHA-256 hash function of the key
        kid: ?[]const u8 = null,

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
                        .alg = try a.dupe(u8, "ES256"),
                        .kty = try a.dupe(u8, "EC"),
                        .crv = try a.dupe(u8, "P-256"),
                        .x = Base64Encoder.encode(x, pub_key[1..33]),
                        .y = Base64Encoder.encode(y, pub_key[33..66]),
                        .d = Base64Encoder.encode(d, d_),
                    };

                    try k.calcKid(); // this will only fail if we run out of memory

                    return k;
                },
            }
        }

        pub fn validate(self: *const @This(), s: []const u8, d: []const u8, options: struct { hint: ?[]const u8 = null }) !bool {
            if (std.mem.eql(u8, "EC", self.kty)) {
                const alg = if (self.alg) |alg| blk1: {
                    break :blk1 alg;
                } else if (options.hint) |h| blk2: {
                    break :blk2 h;
                } else {
                    return error.UnknownAlg;
                };

                if (std.mem.eql(u8, alg, "ES256")) {
                    var sig: [64]u8 = .{0} ** 64;
                    var sec1: [65]u8 = .{0} ** 65;
                    sec1[0] = 0x04;

                    if (self.x) |x_| {
                        try Base64Decoder.decode(sec1[1..33], x_);
                    } else {
                        return error.MissingX;
                    }

                    if (self.y) |y_| {
                        try Base64Decoder.decode(sec1[33..], y_);
                    } else {
                        return error.MissingY;
                    }

                    try Base64Decoder.decode(&sig, s);

                    const pk = try ES256.PublicKey.fromSec1(&sec1);
                    const sig_ = ES256.Signature.fromBytes(sig);

                    sig_.verify(d, pk) catch {
                        return false;
                    };
                    return true;
                } else {
                    return error.UnsupportedAlg;
                }
            } else {
                return error.UnsupportedKty;
            }
        }

        pub fn deinit(self: *const @This(), a: Allocator) void {
            if (self.alg) |alg| {
                a.free(alg);
            }
            a.free(self.kty);
            if (self.crv) |crv| {
                a.free(crv);
            }
            if (self.x) |x| {
                a.free(x);
            }
            if (self.y) |y| {
                a.free(y);
            }
            if (self.d) |d| {
                a.free(d);
            }
            if (self.kid) |kid| {
                a.free(kid);
            }
        }

        /// Calculate the [thumb-print](https://www.rfc-editor.org/rfc/rfc7638.html) of the key and set it as kid.
        pub fn calcKid(self: *@This(), a: Allocator) !void {
            var tp = std.ArrayList(u8).init(a);
            defer tp.deinit();

            if (std.mem.eql(u8, self.kty, "EC")) {
                // Construct a JSON object containing only the required members
                // of a JWK with no whitespace or line breaks in lexographical
                // order.
                try tp.appendSlice("{\"crv\":\"");
                try tp.appendSlice(self.crv.?);
                try tp.appendSlice("\",\"kty\":\"");
                try tp.appendSlice(self.kty);
                try tp.appendSlice("\",\"x\":\"");
                try tp.appendSlice(self.x.?);
                try tp.appendSlice("\",\"y\":\"");
                try tp.appendSlice(self.y.?);
                try tp.appendSlice("\"}");

                // Hash the JSON object with SHA-256
                var kid: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(tp.items, &kid, .{});
                var kid_ = try a.alloc(u8, Base64Encoder.calcSize(32));
                self.kid = Base64Encoder.encode(kid_, &kid);
            }
        }
    };
};

pub const TrustChainEntry = struct {
    /// The issuer of the trust statement.
    /// For leaf and root entries iss and sub are the same. For
    /// all other entries iss is the entity that issued the
    /// statement for the entity in sub.
    iss: []const u8,
    /// The subject of the statement.
    sub: []const u8,
    /// JWS containing the trust statement for sub
    entity_statement: []const u8,

    pub fn deinit(self: *const @This(), a: Allocator) void {
        a.free(self.iss);
        a.free(self.sub);
        a.free(self.entity_statement);
    }
};

pub const TrustChain = []const []const u8;

/// Validate the given trust chain.
///
/// This function makes the following assumptions:
/// 1. The trust chain starts with a statement of the leaf over itself
/// 2. The trust chain ends with a statement of the TA over itself
///
/// https://openid.net/specs/openid-federation-1_0.html#section-9.2
pub fn validateTrustChain(tc: TrustChain, epoch: i64, a: Allocator) !void {
    if (tc.len < 3) {
        // 1. leaf -> leaf
        // 2. TA -> leaf
        // 3. TA -> TA
        std.log.err("expected at least 3 statements", .{});
        return error.TrustChainTooShort;
    }

    var i: usize = 0;
    var this: JWS = try JWS.fromSlice(tc[0], a);
    defer this.deinit(a);
    var next: ?JWS = try JWS.fromSlice(tc[1], a);
    defer {
        if (next != null) {
            next.?.deinit(a);
        }
    }

    while (i < tc.len - 1) : (i += 1) {
        if (i > 0) {
            next = try JWS.fromSlice(tc[i + 1], a);
        }
        // Verify that iat has a value in the past.
        if (this.payload.iat >= epoch) {
            return error.Iat;
        }
        // Verify that exp has a value that is in the future.
        if (this.payload.exp <= epoch) {
            return error.Exp;
        }

        if (this.header.kid == null) {
            std.log.err("missing kid for ES[{d}]", .{i});
            return error.MissingKid;
        }
        if (this.header.alg == null) {
            std.log.err("missing alg for ES[{d}]", .{i});
            return error.MissingAlg;
        }

        // for EC[0]:
        if (i == 0) {
            // verify that iss == sub
            if (!std.mem.eql(u8, this.payload.iss, this.payload.sub)) {
                std.log.err("iss != sub for leaf", .{});
                return error.LeafIssSubMismatch;
            }

            // verify that its signature validates with a public key in ES[0]["jwks"]
            outer: for (this.payload.jwks.keys) |key| {
                if (key.kid) |kid| {
                    if (std.mem.eql(u8, kid, this.header.kid.?)) {
                        const valid = try key.validate(this.sig, this.data, .{
                            .hint = this.header.alg.?,
                        });

                        if (!valid) {
                            std.log.err("validation of EC[{d}] failed", .{i});
                            return error.ValidationFailure;
                        }

                        break :outer;
                    }
                }
            } else {
                std.log.err("no key found for EC[{d}]", .{i});
                return error.KeyMissing;
            }
        }

        // verify that ES[i]["iss"] == ES[i+1]["sub"]
        if (!std.mem.eql(u8, this.payload.iss, next.?.payload.sub)) {
            std.log.err("iss != sub", .{});
            return error.IssSubMismatch;
        }

        // verify the signature of ES[j] with a public key in ES[j+1]["jwks"]
        outer: for (next.?.payload.jwks.keys) |key| {
            if (key.kid) |kid| {
                if (std.mem.eql(u8, kid, this.header.kid.?)) {
                    const valid = try key.validate(this.sig, this.data, .{
                        .hint = this.header.alg.?,
                    });

                    if (!valid) {
                        std.log.err("validation of EC[{d}] failed", .{i});
                        return error.ValidationFailure;
                    }

                    break :outer;
                }
            }
        } else {
            std.log.err("no key found for EC[{d}]", .{i});
            return error.KeyMissing;
        }

        this.deinit(a);
        this = next.?;
        next = null;
    }

    // now only the TA es left (this)

    // TODO: verify iss == sub

    outer: for (this.payload.jwks.keys) |key| {
        if (key.kid) |kid| {
            if (std.mem.eql(u8, kid, this.header.kid.?)) {
                const valid = try key.validate(this.sig, this.data, .{
                    .hint = this.header.alg.?,
                });

                if (!valid) {
                    std.log.err("validation of EC[{d}] (TA) failed", .{i});
                    return error.ValidationFailure;
                }

                break :outer;
            }
        }
    } else {
        std.log.err("no key found for EC[{d}] (TA)", .{i});
        return error.KeyMissing;
    }
}

test "jwk calc kid #1" {
    const a = std.testing.allocator;

    var k = jwk.Key{
        .kty = try a.dupe(u8, "EC"),
        .crv = try a.dupe(u8, "P-256"),
        .x = try a.dupe(u8, "X2S1dFE7zokQDST0bfHdlOWxOc8FC1l4_sG1Kwa4l4s"),
        .y = try a.dupe(u8, "812nU6OCKxgc2ZgSPt_dkXbYldG_smHJi4wXByDHc6g"),
    };
    defer k.deinit(a);

    try k.calcKid(a);

    try std.testing.expectEqualStrings("-kErIK8gkYwo7XcKkcIA3lnUa4kwGctx2B5FQPu1pBw", k.kid.?);
}

test "jwk deserialize #1" {
    const a = std.testing.allocator;

    const k =
        \\ {"kty": "EC", "crv": "P-256", "x": "k6AW3vOy75xXoc_GgZJqNrOPsfknfphqMItfBsO3fT4", "y": "13AY9eD5yr010oib3vCAEn9bblUj1DMSS3OhTKw0MHA", "kid": "NTlhMTZhOGFiMjVjMzEwZDcwYWM1MjBlMjI3MmNjOTk4MWU2OWM2NDgzOGQ4YmJiOTI3M2EzZTBiMDM0OWE3Nw"}
    ;
    var k2 = try std.json.parseFromSliceLeaky(jwk.Key, a, k, .{
        .allocate = .alloc_always,
    });
    defer k2.deinit(a);

    try std.testing.expectEqualStrings("EC", k2.kty);
    try std.testing.expectEqualStrings("P-256", k2.crv.?);
    try std.testing.expectEqualStrings("k6AW3vOy75xXoc_GgZJqNrOPsfknfphqMItfBsO3fT4", k2.x.?);
    try std.testing.expectEqualStrings("13AY9eD5yr010oib3vCAEn9bblUj1DMSS3OhTKw0MHA", k2.y.?);
}

test "TC entry #1" {
    const a = std.testing.allocator;

    const e =
        \\        {
        \\      "iss": "sp.edu",
        \\      "sub": "sp.edu",
        \\      "entity_statement": "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifQo.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJ0YS5jb20iLF0sImp3a3MiOiB7ImtleXMiOiBbeyJrdHkiOiAiRUMiLCJjcnYiOiAiUC0yNTYiLCJ4IjogIms2QVczdk95NzV4WG9jX0dnWkpxTnJPUHNma25mcGhxTUl0ZkJzTzNmVDQiLCJ5IjogIjEzQVk5ZUQ1eXIwMTBvaWIzdkNBRW45YmJsVWoxRE1TUzNPaFRLdzBNSEEiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifV19LCJpc3MiOiAic3AuZWR1IiwiaWF0IjogMTcwODExODIxMSwiZXhwIjogMTcwODIwNDYxMX0.MEUCIHXmJFxEZURy3DQ5R2aUgelhX_i1Y4lCUF-TCuqOA7X4AiEAsvVx_-wroi4FRTAB6_0cT5baf9065nz6NgjzPriWhW0"                             
        \\    }
    ;

    const e2 = try std.json.parseFromSliceLeaky(TrustChainEntry, a, e, .{ .allocate = .alloc_always });
    defer e2.deinit(a);

    try std.testing.expectEqualStrings("sp.edu", e2.iss);
    try std.testing.expectEqualStrings("sp.edu", e2.sub);
    try std.testing.expectEqualSlices(u8, "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifQo.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJ0YS5jb20iLF0sImp3a3MiOiB7ImtleXMiOiBbeyJrdHkiOiAiRUMiLCJjcnYiOiAiUC0yNTYiLCJ4IjogIms2QVczdk95NzV4WG9jX0dnWkpxTnJPUHNma25mcGhxTUl0ZkJzTzNmVDQiLCJ5IjogIjEzQVk5ZUQ1eXIwMTBvaWIzdkNBRW45YmJsVWoxRE1TUzNPaFRLdzBNSEEiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifV19LCJpc3MiOiAic3AuZWR1IiwiaWF0IjogMTcwODExODIxMSwiZXhwIjogMTcwODIwNDYxMX0.MEUCIHXmJFxEZURy3DQ5R2aUgelhX_i1Y4lCUF-TCuqOA7X4AiEAsvVx_-wroi4FRTAB6_0cT5baf9065nz6NgjzPriWhW0", e2.entity_statement);
}

test "JWS #1" {
    const a = std.testing.allocator;

    const jws = "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifQo.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJ0YS5jb20iXSwiandrcyI6IHsia2V5cyI6IFt7Imt0eSI6ICJFQyIsImNydiI6ICJQLTI1NiIsIngiOiAiazZBVzN2T3k3NXhYb2NfR2daSnFOck9Qc2ZrbmZwaHFNSXRmQnNPM2ZUNCIsInkiOiAiMTNBWTllRDV5cjAxMG9pYjN2Q0FFbjliYmxVajFETVNTM09oVEt3ME1IQSIsImtpZCI6ICJOVGxoTVRaaE9HRmlNalZqTXpFd1pEY3dZV00xTWpCbE1qSTNNbU5qT1RrNE1XVTJPV00yTkRnek9HUTRZbUppT1RJM00yRXpaVEJpTURNME9XRTNOdyJ9XX0sImlzcyI6ICJzcC5lZHUiLCJpYXQiOiAxNzA4MTE4MjExLCJleHAiOiAxNzA4MjA0NjExfQ.YcqT1kx4Dwz8sQV2dUN9wOCU85O7jOruYaLZSuU19YYAF6IUMi8Cl6tjUtKlo2YK6_bZrWJcIqgfIloWfkX6mw";

    const jws2 = try JWS.fromSlice(jws, a);
    defer jws2.deinit(a);

    try std.testing.expectEqualSlices(u8, "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifQo.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJ0YS5jb20iXSwiandrcyI6IHsia2V5cyI6IFt7Imt0eSI6ICJFQyIsImNydiI6ICJQLTI1NiIsIngiOiAiazZBVzN2T3k3NXhYb2NfR2daSnFOck9Qc2ZrbmZwaHFNSXRmQnNPM2ZUNCIsInkiOiAiMTNBWTllRDV5cjAxMG9pYjN2Q0FFbjliYmxVajFETVNTM09oVEt3ME1IQSIsImtpZCI6ICJOVGxoTVRaaE9HRmlNalZqTXpFd1pEY3dZV00xTWpCbE1qSTNNbU5qT1RrNE1XVTJPV00yTkRnek9HUTRZbUppT1RJM00yRXpaVEJpTURNME9XRTNOdyJ9XX0sImlzcyI6ICJzcC5lZHUiLCJpYXQiOiAxNzA4MTE4MjExLCJleHAiOiAxNzA4MjA0NjExfQ", jws2.data);

    try std.testing.expectEqualSlices(u8, "YcqT1kx4Dwz8sQV2dUN9wOCU85O7jOruYaLZSuU19YYAF6IUMi8Cl6tjUtKlo2YK6_bZrWJcIqgfIloWfkX6mw", jws2.sig);

    try std.testing.expectEqualStrings("ES256", jws2.header.alg.?);
}

test "JWS validation #1" {
    const a = std.testing.allocator;

    const jws = "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifQo.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJ0YS5jb20iXSwiandrcyI6IHsia2V5cyI6IFt7Imt0eSI6ICJFQyIsImNydiI6ICJQLTI1NiIsIngiOiAiazZBVzN2T3k3NXhYb2NfR2daSnFOck9Qc2ZrbmZwaHFNSXRmQnNPM2ZUNCIsInkiOiAiMTNBWTllRDV5cjAxMG9pYjN2Q0FFbjliYmxVajFETVNTM09oVEt3ME1IQSIsImtpZCI6ICJOVGxoTVRaaE9HRmlNalZqTXpFd1pEY3dZV00xTWpCbE1qSTNNbU5qT1RrNE1XVTJPV00yTkRnek9HUTRZbUppT1RJM00yRXpaVEJpTURNME9XRTNOdyJ9XX0sImlzcyI6ICJzcC5lZHUiLCJpYXQiOiAxNzA4MTE4MjExLCJleHAiOiAxNzA4MjA0NjExfQ.YcqT1kx4Dwz8sQV2dUN9wOCU85O7jOruYaLZSuU19YYAF6IUMi8Cl6tjUtKlo2YK6_bZrWJcIqgfIloWfkX6mw";

    const jws2 = try JWS.fromSlice(jws, a);
    defer jws2.deinit(a);

    try std.testing.expect(try jws2.payload.jwks.keys[0].validate(
        jws2.sig,
        jws2.data,
        .{
            .hint = jws2.header.alg.?,
        },
    ));
}

test "trust chain validation #1" {
    const a = std.testing.allocator;

    const tc =
        \\ [
        \\      "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifQo.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJ0YS5jb20iXSwiandrcyI6IHsia2V5cyI6IFt7Imt0eSI6ICJFQyIsImNydiI6ICJQLTI1NiIsIngiOiAiazZBVzN2T3k3NXhYb2NfR2daSnFOck9Qc2ZrbmZwaHFNSXRmQnNPM2ZUNCIsInkiOiAiMTNBWTllRDV5cjAxMG9pYjN2Q0FFbjliYmxVajFETVNTM09oVEt3ME1IQSIsImtpZCI6ICJOVGxoTVRaaE9HRmlNalZqTXpFd1pEY3dZV00xTWpCbE1qSTNNbU5qT1RrNE1XVTJPV00yTkRnek9HUTRZbUppT1RJM00yRXpaVEJpTURNME9XRTNOdyJ9XX0sImlzcyI6ICJzcC5lZHUiLCJpYXQiOiAxNzA4MTE4MjExLCJleHAiOiAxNzA4MjA0NjExfQ.YcqT1kx4Dwz8sQV2dUN9wOCU85O7jOruYaLZSuU19YYAF6IUMi8Cl6tjUtKlo2YK6_bZrWJcIqgfIloWfkX6mw",
        \\       "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiWVdObE16QmlOREkzTjJFek1ETXlaamcxTW1JeVpUWXdZMkpqWVdKbE5tVmlOamMwTkdWbVptSTFPV1V6TmpsaE16UXdNek5tTURBMk9UVmtPREZoWmcifQ.eyJzdWIiOiAic3AuZWR1IiwiYXV0aG9yaXR5X2hpbnRzIjogWyJpbnQuY29tIl0sImp3a3MiOiB7ImtleXMiOiBbeyJrdHkiOiAiRUMiLCJjcnYiOiAiUC0yNTYiLCJ4IjogIms2QVczdk95NzV4WG9jX0dnWkpxTnJPUHNma25mcGhxTUl0ZkJzTzNmVDQiLCJ5IjogIjEzQVk5ZUQ1eXIwMTBvaWIzdkNBRW45YmJsVWoxRE1TUzNPaFRLdzBNSEEiLCJraWQiOiAiTlRsaE1UWmhPR0ZpTWpWak16RXdaRGN3WVdNMU1qQmxNakkzTW1Oak9UazRNV1UyT1dNMk5EZ3pPR1E0WW1KaU9USTNNMkV6WlRCaU1ETTBPV0UzTncifV19LCJpc3MiOiAiaW50LmVkdSIsImlhdCI6IDE3MDgxMTgyMTEsImV4cCI6IDE3MDgyMDQ2MTF9.MhNac4cLhBhXHTSSRaJ25tpMjhzUMYbA0ptLXwaQtfzikM-UmfSc6W7zhfApnWSugR8iyfgdaHFXz8BtyKkb6w",
        \\       "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTUdKbVltTTRObUZtWkRKaU1EUXdZbUZpTVdNelpHRTBNRGs1TnpReFptUXhaak5qTkRrMk1EYzNaRFpqTnpjMll6STBPRFJrWlRJNU5UazBNV0l5WlEifQ.eyJzdWIiOiAiaW50LmVkdSIsImF1dGhvcml0eV9oaW50cyI6IFsidGEuY29tIl0sImp3a3MiOiB7ImtleXMiOiBbeyJrdHkiOiAiRUMiLCJjcnYiOiAiUC0yNTYiLCJ4IjogInBFWEFUcUc5NnN4MVRTLXhqRE9Jb1BWZEZULWdpRW1vZF9pVVZRX0JBZjgiLCJ5IjogImZRbjVEZVIwb01FNWRYdFBVNk92Q1BOa2ZtUXI3dkJkUjBRV3pJajBKbFEiLCJraWQiOiAiWVdObE16QmlOREkzTjJFek1ETXlaamcxTW1JeVpUWXdZMkpqWVdKbE5tVmlOamMwTkdWbVptSTFPV1V6TmpsaE16UXdNek5tTURBMk9UVmtPREZoWmcifV19LCJpc3MiOiAidGEuY29tIiwiaWF0IjogMTcwODExODIxMSwiZXhwIjogMTcwODIwNDYxMX0.6neU5p0RPWg1BiB5nNheb4OZD6xxLmblPEWak7YtwNc8l2J7tAB28zTbOnQlsaaC_vG_A5Dr-0deyGf4Vh8M9Q",
        \\       "eyJhbGciOiAiRVMyNTYiLCJraWQiOiAiTUdKbVltTTRObUZtWkRKaU1EUXdZbUZpTVdNelpHRTBNRGs1TnpReFptUXhaak5qTkRrMk1EYzNaRFpqTnpjMll6STBPRFJrWlRJNU5UazBNV0l5WlEifQ.eyJzdWIiOiAidGEuY29tIiwiandrcyI6IHsia2V5cyI6IFt7Imt0eSI6ICJFQyIsImNydiI6ICJQLTI1NiIsIngiOiAicGJoV2RNYVE2cDk3YWpGY2V1S0ZKa2RmY21IZGtqekZocDFheXBvSFpsYyIsInkiOiAiUmZiS05RbkhvR1VrVXA0aDhGel9jRFNPVmRrNlJOYkIwbVI1N25OLUR6VSIsImtpZCI6ICJNR0ptWW1NNE5tRm1aREppTURRd1ltRmlNV016WkdFME1EazVOelF4Wm1ReFpqTmpORGsyTURjM1pEWmpOemMyWXpJME9EUmtaVEk1TlRrME1XSXlaUSJ9XX0sImlzcyI6ICJ0YS5jb20iLCJpYXQiOiAxNzA4MTE4MjExLCJleHAiOiAxNzA4MjA0NjExfQ.2iNX2fH4TLteeWzJO7QevgJxHGP09OLu7iYVeYwgggrxng7d78Vpjb9Xv5X3q48PEv7Sb9m7bL5UW1YBNqLz0g"
        \\ ]
    ;

    const tc2 = try std.json.parseFromSliceLeaky(TrustChain, a, tc, .{ .allocate = .alloc_always });
    defer {
        for (tc2) |ec| {
            a.free(ec);
        }
        a.free(tc2);
    }

    try validateTrustChain(tc2, 1708118300, a);
}
