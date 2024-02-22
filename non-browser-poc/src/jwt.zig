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
        //std.log.info("{s}", .{h});

        const ps = try Base64Decoder.calcSizeForSlice(s[d1 + 1 .. d2]);
        var p = try a.alloc(u8, ps);
        defer a.free(p);
        try Base64Decoder.decode(p, s[d1 + 1 .. d2]);
        //std.log.info("{s}", .{p});

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
    iss: []const u8,
    /// Subject claim: identifies the principal that is the subject of the JWT.
    sub: []const u8,
    /// The time the statement was issued in seconds form 1970-01-01T0:0:0Z (epoch).
    iat: i64 = 0,
    /// Expiration time after which the statement MUST NOT be accepted (epoch).
    exp: i64 = 0,
    /// A set of public signing keys.
    jwks: struct {
        keys: []const jwk.Key = &.{},
    } = .{},
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

test "this test documents the current problem when querying https://trust-anchor.testbed.oidcfed.incubator.geant.org" {
    const a = std.testing.allocator;

    const x =
        \\        {
        \\  "iss": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/",
        \\  "sub": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/",
        \\  "iat": 1648758030,
        \\  "exp": 1650730827,
        \\  "trust_marks": [],
        \\  "metadata": {
        \\    "openid_provider": {
        \\      "authorization_endpoint": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/authorization",
        \\      "revocation_endpoint": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/revocation/",
        \\      "id_token_encryption_alg_values_supported": [
        \\        "RSA-OAEP"
        \\      ],
        \\      "id_token_encryption_enc_values_supported": [
        \\        "A128CBC-HS256"
        \\      ],
        \\      "token_endpoint": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/token/",
        \\      "userinfo_endpoint": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/userinfo/",
        \\      "introspection_endpoint": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/introspection/",
        \\      "claims_parameter_supported": true,
        \\      "contacts": [
        \\        "ops@https://idp.it"
        \\      ],
        \\      "client_registration_types_supported": [
        \\        "automatic"
        \\      ],
        \\      "code_challenge_methods_supported": [
        \\        "S256"
        \\      ],
        \\      "request_authentication_methods_supported": {
        \\        "ar": [
        \\          "request_object"
        \\        ]
        \\      },
        \\      "acr_values_supported": [
        \\        "https://www.spid.gov.it/SpidL1",
        \\        "https://www.spid.gov.it/SpidL2",
        \\        "https://www.spid.gov.it/SpidL3"
        \\      ],
        \\      "claims_supported": [
        \\        "https://attributes.spid.gov.it/spidCode",
        \\        "https://attributes.spid.gov.it/name",
        \\        "https://attributes.spid.gov.it/familyName",
        \\        "https://attributes.spid.gov.it/placeOfBirth",
        \\        "https://attributes.spid.gov.it/countyOfBirth",
        \\        "https://attributes.spid.gov.it/dateOfBirth",
        \\        "https://attributes.spid.gov.it/gender",
        \\        "https://attributes.spid.gov.it/companyName",
        \\        "https://attributes.spid.gov.it/registeredOffice",
        \\        "https://attributes.spid.gov.it/fiscalNumber",
        \\        "https://attributes.spid.gov.it/ivaCode",
        \\        "https://attributes.spid.gov.it/idCard",
        \\        "https://attributes.spid.gov.it/mobilePhone",
        \\        "https://attributes.spid.gov.it/email",
        \\        "https://attributes.spid.gov.it/address",
        \\        "https://attributes.spid.gov.it/expirationDate",
        \\        "https://attributes.spid.gov.it/digitalAddress"
        \\      ],
        \\      "grant_types_supported": [
        \\        "authorization_code",
        \\        "refresh_token"
        \\      ],
        \\      "id_token_signing_alg_values_supported": [
        \\        "RS256",
        \\        "ES256"
        \\      ],
        \\      "issuer": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/",
        \\      "jwks": {
        \\        "keys": [
        \\          {
        \\            "kty": "RSA",
        \\            "use": "sig",
        \\            "n": "01_4aI2Lu5ggsElmRkE_S_a83V_szXU0txV4db2hmJ8HR1Y2s7PsZZ5-emGpnTydGrR3n-QExeEEIcFt_a06Ryiink34RQcKoGXUDBMBU0Bu8G7NcZ99YX6yeG9wFi4xs-WviTPmtPqijkz6jm1_ltWDcwbktfkraIRKKggZaEl9ldtsFr2wSpin3AXuGIdeJ0hZqhF92ODBLGjJlaIL9KlwopDy56adReVnraawSdrxmuPGj78IEADNAme2nQNvv9UCu0FkAn5St1bKds3Gpv26W0kjr1gZLsmQrj9lTcDk_KbAwfEY__P7se62kusoSuKMTQqUG1TQpUY7oFGSdw",
        \\            "e": "AQAB",
        \\            "kid": "dB67gL7ck3TFiIAf7N6_7SHvqk0MDYMEQcoGGlkUAAw"
        \\          }
        \\        ]
        \\      },
        \\      "scopes_supported": [
        \\        "openid",
        \\        "offline_access"
        \\      ],
        \\      "logo_uri": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/static/svg/spid-logo-c-lb.svg",
        \\      "organization_name": "SPID OIDC identity provider",
        \\      "op_policy_uri": "https://trust-anchor.testbed.oidcfed.incubator.geant.org/oidc/op/en/website/legal-information/",
        \\      "request_parameter_supported": true,
        \\      "request_uri_parameter_supported": true,
        \\      "require_request_uri_registration": true,
        \\      "response_types_supported": [
        \\        "code"
        \\      ],
        \\      "subject_types_supported": [
        \\        "pairwise",
        \\        "public"
        \\      ],
        \\      "token_endpoint_auth_methods_supported": [
        \\        "private_key_jwt"
        \\      ],
        \\      "token_endpoint_auth_signing_alg_values_supported": [
        \\        "RS256",
        \\        "RS384",
        \\        "RS512",
        \\        "ES256",
        \\        "ES384",
        \\        "ES512"
        \\      ],
        \\      "userinfo_encryption_alg_values_supported": [
        \\        "RSA-OAEP",
        \\        "RSA-OAEP-256"
        \\      ],
        \\      "userinfo_encryption_enc_values_supported": [
        \\        "A128CBC-HS256",
        \\        "A192CBC-HS384",
        \\        "A256CBC-HS512",
        \\        "A128GCM",
        \\        "A192GCM",
        \\        "A256GCM"
        \\      ],
        \\      "userinfo_signing_alg_values_supported": [
        \\        "RS256",
        \\        "RS384",
        \\        "RS512",
        \\        "ES256",
        \\        "ES384",
        \\        "ES512"
        \\      ],
        \\      "request_object_encryption_alg_values_supported": [
        \\        "RSA-OAEP",
        \\        "RSA-OAEP-256"
        \\      ],
        \\      "request_object_encryption_enc_values_supported": [
        \\        "A128CBC-HS256",
        \\        "A192CBC-HS384",
        \\        "A256CBC-HS512",
        \\        "A128GCM",
        \\        "A192GCM",
        \\        "A256GCM"
        \\      ],
        \\      "request_object_signing_alg_values_supported": [
        \\        "RS256",
        \\        "RS384",
        \\        "RS512",
        \\        "ES256",
        \\        "ES384",
        \\        "ES512"
        \\      ]
        \\    }
        \\  },
        \\  "trust_chain": [
        \\    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImNJOHBCdldkSGdjdmxkbUk3SFhiUE1mRmhTS2tmQUNJYm9mc0Q2cTJKdEUiLCJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCJ9.eyJleHAiOjE2NTA5MDE2NDcsImlhdCI6MTY1MDcyODg0NywiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvb3AvIiwic3ViIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvb3AvIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiIxQVlHRjBDX2o1Q1BlWU1SSF9ta2huWXRudk1fQ21kbFdTRkhLOVlFYXMzZ0oxOTIyRG5oRngzRUl3MVUta1p3dzdiZ056NkMxbF8xY3lqa2dCU3VXeE9iT2JLNHpWTFpCR1VaZlhNQk5GbTJoZHI1Vm9MS0xlbXRaSHBCT21kc3hSMVIzVEozMEQwdlktTEpiVXRyd3VSQzhvT0NZSTV3aGNFYzhCNHV0RWV4M1c2ZENqQklqc0dmZEpJcVpIaGZMTjN4d1BNT2prRzVBX3k4V25UVmZHcTlPVWV1YVVuMy1QVnMzTzlMTXBPQmxhVDdHcmVYZ1VxV0FXLXp4VUNzaUhIVVZsOXVJQUdpNU9IdWtJdUJzMkNsQWxNWF9TNm1iTjdfN0tJR3gybVRJcmNnVkJQSmdZb3A5cW5TcWNYdWJfRVFUS3NGdE5HaWdzVUZuRHFGTlEiLCJraWQiOiJjSThwQnZXZEhnY3ZsZG1JN0hYYlBNZkZoU0trZkFDSWJvZnNENnEySnRFIn1dfSwibWV0YWRhdGEiOnsib3BlbmlkX3Byb3ZpZGVyIjp7ImF1dGhvcml6YXRpb25fZW5kcG9pbnQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvb2lkYy9vcC9hdXRob3JpemF0aW9uIiwicmV2b2NhdGlvbl9lbmRwb2ludCI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMC9vaWRjL29wL3Jldm9jYXRpb24vIiwiaWRfdG9rZW5fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSU0EtT0FFUCJdLCJpZF90b2tlbl9lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkIjpbIkExMjhDQkMtSFMyNTYiXSwib3BfbmFtZSI6IkFnZW56aWEgcGVyIGxcdTIwMTlJdGFsaWEgRGlnaXRhbGUiLCJvcF91cmkiOiJodHRwczovL3d3dy5hZ2lkLmdvdi5pdCIsInRva2VuX2VuZHBvaW50IjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvb3AvdG9rZW4vIiwidXNlcmluZm9fZW5kcG9pbnQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvb2lkYy9vcC91c2VyaW5mby8iLCJpbnRyb3NwZWN0aW9uX2VuZHBvaW50IjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL29pZGMvb3AvaW50cm9zcGVjdGlvbi8iLCJjbGFpbXNfcGFyYW1ldGVyX3N1cHBvcnRlZCI6dHJ1ZSwiY29udGFjdHMiOlsib3BzQGh0dHBzOi8vaWRwLml0Il0sImNsaWVudF9yZWdpc3RyYXRpb25fdHlwZXNfc3VwcG9ydGVkIjpbImF1dG9tYXRpYyJdLCJjb2RlX2NoYWxsZW5nZV9tZXRob2RzX3N1cHBvcnRlZCI6WyJTMjU2Il0sInJlcXVlc3RfYXV0aGVudGljYXRpb25fbWV0aG9kc19zdXBwb3J0ZWQiOnsiYXIiOlsicmVxdWVzdF9vYmplY3QiXX0sImFjcl92YWx1ZXNfc3VwcG9ydGVkIjpbImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMSIsImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMiIsImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L1NwaWRMMyJdLCJjbGFpbXNfc3VwcG9ydGVkIjpbImh0dHBzOi8vYXR0cmlidXRlcy5zcGlkLmdvdi5pdC9zcGlkQ29kZSIsImh0dHBzOi8vYXR0cmlidXRlcy5zcGlkLmdvdi5pdC9uYW1lIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLnNwaWQuZ292Lml0L2ZhbWlseU5hbWUiLCJodHRwczovL2F0dHJpYnV0ZXMuc3BpZC5nb3YuaXQvcGxhY2VPZkJpcnRoIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLnNwaWQuZ292Lml0L2NvdW50eU9mQmlydGgiLCJodHRwczovL2F0dHJpYnV0ZXMuc3BpZC5nb3YuaXQvZGF0ZU9mQmlydGgiLCJodHRwczovL2F0dHJpYnV0ZXMuc3BpZC5nb3YuaXQvZ2VuZGVyIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLnNwaWQuZ292Lml0L2NvbXBhbnlOYW1lIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLnNwaWQuZ292Lml0L3JlZ2lzdGVyZWRPZmZpY2UiLCJodHRwczovL2F0dHJpYnV0ZXMuc3BpZC5nb3YuaXQvZmlzY2FsTnVtYmVyIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLnNwaWQuZ292Lml0L2l2YUNvZGUiLCJodHRwczovL2F0dHJpYnV0ZXMuc3BpZC5nb3YuaXQvaWRDYXJkIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLnNwaWQuZ292Lml0L21vYmlsZVBob25lIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLnNwaWQuZ292Lml0L2VtYWlsIiwiaHR0cHM6Ly9hdHRyaWJ1dGVzLnNwaWQuZ292Lml0L2FkZHJlc3MiLCJodHRwczovL2F0dHJpYnV0ZXMuc3BpZC5nb3YuaXQvZXhwaXJhdGlvbkRhdGUiLCJodHRwczovL2F0dHJpYnV0ZXMuc3BpZC5nb3YuaXQvZGlnaXRhbEFkZHJlc3MiXSwiZ3JhbnRfdHlwZXNfc3VwcG9ydGVkIjpbImF1dGhvcml6YXRpb25fY29kZSIsInJlZnJlc2hfdG9rZW4iXSwiaWRfdG9rZW5fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIkVTMjU2Il0sImlzc3VlciI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMC9vaWRjL29wLyIsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiUlNBIiwidXNlIjoic2lnIiwibiI6IjAxXzRhSTJMdTVnZ3NFbG1Sa0VfU19hODNWX3N6WFUwdHhWNGRiMmhtSjhIUjFZMnM3UHNaWjUtZW1HcG5UeWRHclIzbi1RRXhlRUVJY0Z0X2EwNlJ5aWluazM0UlFjS29HWFVEQk1CVTBCdThHN05jWjk5WVg2eWVHOXdGaTR4cy1XdmlUUG10UHFpamt6NmptMV9sdFdEY3dia3Rma3JhSVJLS2dnWmFFbDlsZHRzRnIyd1NwaW4zQVh1R0lkZUowaFpxaEY5Mk9EQkxHakpsYUlMOUtsd29wRHk1NmFkUmVWbnJhYXdTZHJ4bXVQR2o3OElFQUROQW1lMm5RTnZ2OVVDdTBGa0FuNVN0MWJLZHMzR3B2MjZXMGtqcjFnWkxzbVFyajlsVGNEa19LYkF3ZkVZX19QN3NlNjJrdXNvU3VLTVRRcVVHMVRRcFVZN29GR1NkdyIsImUiOiJBUUFCIiwia2lkIjoiZEI2N2dMN2NrM1RGaUlBZjdONl83U0h2cWswTURZTUVRY29HR2xrVUFBdyJ9XX0sInNjb3Blc19zdXBwb3J0ZWQiOlsib3BlbmlkIiwib2ZmbGluZV9hY2Nlc3MiXSwibG9nb191cmkiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvc3RhdGljL3N2Zy9zcGlkLWxvZ28tYy1sYi5zdmciLCJvcmdhbml6YXRpb25fbmFtZSI6IlNQSUQgT0lEQyBpZGVudGl0eSBwcm92aWRlciIsIm9wX3BvbGljeV91cmkiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvb2lkYy9vcC9lbi93ZWJzaXRlL2xlZ2FsLWluZm9ybWF0aW9uLyIsInJlcXVlc3RfcGFyYW1ldGVyX3N1cHBvcnRlZCI6dHJ1ZSwicmVxdWVzdF91cmlfcGFyYW1ldGVyX3N1cHBvcnRlZCI6dHJ1ZSwicmVxdWlyZV9yZXF1ZXN0X3VyaV9yZWdpc3RyYXRpb24iOnRydWUsInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJjb2RlIl0sInN1YmplY3RfdHlwZXNfc3VwcG9ydGVkIjpbInBhaXJ3aXNlIiwicHVibGljIl0sInRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kc19zdXBwb3J0ZWQiOlsicHJpdmF0ZV9rZXlfand0Il0sInRva2VuX2VuZHBvaW50X2F1dGhfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXSwidXNlcmluZm9fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSU0EtT0FFUCIsIlJTQS1PQUVQLTI1NiIsIkVDREgtRVMiLCJFQ0RILUVTK0ExMjhLVyIsIkVDREgtRVMrQTE5MktXIiwiRUNESC1FUytBMjU2S1ciXSwidXNlcmluZm9fZW5jcnlwdGlvbl9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4Q0JDLUhTMjU2IiwiQTE5MkNCQy1IUzM4NCIsIkEyNTZDQkMtSFM1MTIiLCJBMTI4R0NNIiwiQTE5MkdDTSIsIkEyNTZHQ00iXSwidXNlcmluZm9fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXSwicmVxdWVzdF9vYmplY3RfZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSU0EtT0FFUCIsIlJTQS1PQUVQLTI1NiIsIkVDREgtRVMiLCJFQ0RILUVTK0ExMjhLVyIsIkVDREgtRVMrQTE5MktXIiwiRUNESC1FUytBMjU2S1ciXSwicmVxdWVzdF9vYmplY3RfZW5jcnlwdGlvbl9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4Q0JDLUhTMjU2IiwiQTE5MkNCQy1IUzM4NCIsIkEyNTZDQkMtSFM1MTIiLCJBMTI4R0NNIiwiQTE5MkdDTSIsIkEyNTZHQ00iXSwicmVxdWVzdF9vYmplY3Rfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXX19LCJhdXRob3JpdHlfaGludHMiOlsiaHR0cDovLzEyNy4wLjAuMTo4MDAwLyJdfQ.n4Iut7R3JwLSCnH0PMoF3huC0Ie_XBqvKX666OJqw01XMWSD7fgwGmSxhd7DoJ4dhQi31iLGuvYAmd0jct6fY6Q2MXVOGT8_jYh8roAyDDP-MdfmOHp0OfAyx8guuiELM-oyfNdRlcWtP0JRxWLW57JmR572Xr-UcOV8mpbYFkUJ0pixYZGMtYd1qLUahutSurD0I-6mCnEc5OiFctFwXjVcJ5yVby0qc5WMEKlzneLJifzgpJu1KVW361_YHlc_lJW3RLr6NOj6WdHUy7EF4MrztdTK8268SOHW66J-tPCLGCGe8JwC_x0OgP39_6SPHrtEgojAd6hQnFtowXVwvg",
        \\    "eyJhbGciOiJSUzI1NiIsImtpZCI6IkJYdmZybG5oQU11SFIwN2FqVW1BY0JSUWNTem13MGNfUkFnSm5wUy05V1EiLCJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCJ9.eyJleHAiOjE2NTA3MzA4MjcsImlhdCI6MTY1MDcyODg0NywiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwLyIsInN1YiI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMC8iLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsImUiOiJBUUFCIiwibiI6Im84SW9sUmpabGt6Y3QtNDhyaHJWbFRuWVUxcGtNYlZKRC1EVTA1b01TOVJWR3JzRnlwZzk4bS1LdzRINHFOUHlRVngyT1FPUmkteFNoZ2s3SFUtZ0tfMnBWZ3VZa3YwNkZhakxfZWRFQXFxc3F0Xzc0UWYyV0xSQzVwZkpHX3o5T1B6WThKR3lrLXozU2JlSE5fQlhLSThHWTVFNFdVMlNzdG1ROWZ5TDRDeHRSZmpVaWE4bGltVENfM01PcFQzemk1bnIwM2pmYmpwbmpnYTUxcVh1cnhubHpjM2FfeGprNVJBQXBLeFV2TndoSjI3NU0wQ21COTlEalB3RjZCTHZVZ0pxZ3lDcFVPbjM2TE9oSTRGcXVWcWhxaGl3S2xNbWlNZTN5eTB5TlE3RlhCV3hqemhleGJweWMzVnU3ekZJSFBBY0M0VXlJUWhjM3dhRWoydmlYdyIsImtpZCI6IkJYdmZybG5oQU11SFIwN2FqVW1BY0JSUWNTem13MGNfUkFnSm5wUy05V1EifV19LCJtZXRhZGF0YSI6eyJmZWRlcmF0aW9uX2VudGl0eSI6eyJjb250YWN0cyI6WyJvcHNAbG9jYWxob3N0Il0sImZlZGVyYXRpb25fZmV0Y2hfZW5kcG9pbnQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvZmV0Y2gvIiwiZmVkZXJhdGlvbl9yZXNvbHZlX2VuZHBvaW50IjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwL3Jlc29sdmUvIiwiZmVkZXJhdGlvbl9zdGF0dXNfZW5kcG9pbnQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvdHJ1c3RfbWFya19zdGF0dXMvIiwiaG9tZXBhZ2VfdXJpIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwIiwibmFtZSI6ImV4YW1wbGUgVEEiLCJmZWRlcmF0aW9uX2xpc3RfZW5kcG9pbnQiOiJodHRwOi8vMTI3LjAuMC4xOjgwMDAvbGlzdC8ifX0sInRydXN0X21hcmtzX2lzc3VlcnMiOnsiaHR0cHM6Ly93d3cuc3BpZC5nb3YuaXQvY2VydGlmaWNhdGlvbi9ycC9wdWJsaWMiOlsiaHR0cHM6Ly9yZWdpc3RyeS5zcGlkLmFnaWQuZ292Lml0IiwiaHR0cHM6Ly9wdWJsaWMuaW50ZXJtZWRpYXJ5LnNwaWQuaXQiXSwiaHR0cHM6Ly93d3cuc3BpZC5nb3YuaXQvY2VydGlmaWNhdGlvbi9ycC9wcml2YXRlIjpbImh0dHBzOi8vcmVnaXN0cnkuc3BpZC5hZ2lkLmdvdi5pdCIsImh0dHBzOi8vcHJpdmF0ZS5vdGhlci5pbnRlcm1lZGlhcnkuaXQiXSwiaHR0cHM6Ly9zZ2QuYWEuaXQvb25ib2FyZGluZyI6WyJodHRwczovL3NnZC5hYS5pdCJdfSwiY29uc3RyYWludHMiOnsibWF4X3BhdGhfbGVuZ3RoIjoxfX0.fMQvcBAK4hFMJ2EU6dIR4wHTfNj_8yxohS_QcPHSPuFgMwqnhmAou6xDpv3L0TsibuU7Gnc4GRc2El8_9wVuXsUJOsAa2DpDJg6zoIa-XmLKjFKTpRDj735vcZb_wJqlXPTWI3AGRb1xAUKYF7BIg0KxIDjzOkLqkz8-XfmyHhESgnVXudITRaFad1nijYb1jb7ivLvgV3wdZ5IsKDaDV5Ys9ICTmSnMAEEmwYKWltWHj4bcqLs_diXL14wTJyzySvqG7FwSrVOS4qTdlfEqMuxOJ0b4Nr7L92DtG9KxxdMluBLZDmRwoL3rKu24vDvgfzftAxaoR57QH3IC4Qvp8A",
        \\    [
        \\      "eyJhbGciOiJSUzI1NiIsImtpZCI6IkJYdmZybG5oQU11SFIwN2FqVW1BY0JSUWNTem13MGNfUkFnSm5wUy05V1EiLCJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCJ9.eyJleHAiOjE2NTA5MDE2NDcsImlhdCI6MTY1MDcyODg0NywiaXNzIjoiaHR0cDovLzEyNy4wLjAuMTo4MDAwLyIsInN1YiI6Imh0dHA6Ly8xMjcuMC4wLjE6ODAwMC9vaWRjL29wLyIsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiUlNBIiwiZSI6IkFRQUIiLCJuIjoiMUFZR0YwQ19qNUNQZVlNUkhfbWtobll0bnZNX0NtZGxXU0ZISzlZRWFzM2dKMTkyMkRuaEZ4M0VJdzFVLWtad3c3YmdOejZDMWxfMWN5amtnQlN1V3hPYk9iSzR6VkxaQkdVWmZYTUJORm0yaGRyNVZvTEtMZW10WkhwQk9tZHN4UjFSM1RKMzBEMHZZLUxKYlV0cnd1UkM4b09DWUk1d2hjRWM4QjR1dEVleDNXNmRDakJJanNHZmRKSXFaSGhmTE4zeHdQTU9qa0c1QV95OFduVFZmR3E5T1VldWFVbjMtUFZzM085TE1wT0JsYVQ3R3JlWGdVcVdBVy16eFVDc2lISFVWbDl1SUFHaTVPSHVrSXVCczJDbEFsTVhfUzZtYk43XzdLSUd4Mm1USXJjZ1ZCUEpnWW9wOXFuU3FjWHViX0VRVEtzRnROR2lnc1VGbkRxRk5RIiwia2lkIjoiY0k4cEJ2V2RIZ2N2bGRtSTdIWGJQTWZGaFNLa2ZBQ0lib2ZzRDZxMkp0RSJ9XX0sIm1ldGFkYXRhX3BvbGljeSI6eyJvcGVuaWRfcHJvdmlkZXIiOnsic3ViamVjdF90eXBlc19zdXBwb3J0ZWQiOnsidmFsdWUiOlsicGFpcndpc2UiXX0sImlkX3Rva2VuX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOnsic3Vic2V0X29mIjpbIlJTMjU2IiwiUlMzODQiLCJSUzUxMiIsIkVTMjU2IiwiRVMzODQiLCJFUzUxMiJdfSwidXNlcmluZm9fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6eyJzdWJzZXRfb2YiOlsiUlMyNTYiLCJSUzM4NCIsIlJTNTEyIiwiRVMyNTYiLCJFUzM4NCIsIkVTNTEyIl19LCJ0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZHNfc3VwcG9ydGVkIjp7InZhbHVlIjpbInByaXZhdGVfa2V5X2p3dCJdfSwidXNlcmluZm9fZW5jcnlwdGlvbl9hbGdfdmFsdWVzX3N1cHBvcnRlZCI6eyJzdWJzZXRfb2YiOlsiUlNBLU9BRVAiLCJSU0EtT0FFUC0yNTYiLCJFQ0RILUVTIiwiRUNESC1FUytBMTI4S1ciLCJFQ0RILUVTK0ExOTJLVyIsIkVDREgtRVMrQTI1NktXIl19LCJ1c2VyaW5mb19lbmNyeXB0aW9uX2VuY192YWx1ZXNfc3VwcG9ydGVkIjp7InN1YnNldF9vZiI6WyJBMTI4Q0JDLUhTMjU2IiwiQTE5MkNCQy1IUzM4NCIsIkEyNTZDQkMtSFM1MTIiLCJBMTI4R0NNIiwiQTE5MkdDTSIsIkEyNTZHQ00iXX0sInJlcXVlc3Rfb2JqZWN0X2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOnsic3Vic2V0X29mIjpbIlJTQS1PQUVQIiwiUlNBLU9BRVAtMjU2IiwiRUNESC1FUyIsIkVDREgtRVMrQTEyOEtXIiwiRUNESC1FUytBMTkyS1ciLCJFQ0RILUVTK0EyNTZLVyJdfSwicmVxdWVzdF9vYmplY3RfZW5jcnlwdGlvbl9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6eyJzdWJzZXRfb2YiOlsiQTEyOENCQy1IUzI1NiIsIkExOTJDQkMtSFMzODQiLCJBMjU2Q0JDLUhTNTEyIiwiQTEyOEdDTSIsIkExOTJHQ00iLCJBMjU2R0NNIl19LCJyZXF1ZXN0X29iamVjdF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjp7InN1YnNldF9vZiI6WyJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXX19fSwidHJ1c3RfbWFya3MiOlt7ImlkIjoiaHR0cHM6Ly93d3cuc3BpZC5nb3YuaXQvb3BlbmlkLWZlZGVyYXRpb24vYWdyZWVtZW50L29wLXB1YmxpYy8iLCJ0cnVzdF9tYXJrIjoiZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklrSllkbVp5Ykc1b1FVMTFTRkl3TjJGcVZXMUJZMEpTVVdOVGVtMTNNR05mVWtGblNtNXdVeTA1VjFFaUxDSjBlWEFpT2lKMGNuVnpkQzF0WVhKcksycDNkQ0o5LmV5SnBjM01pT2lKb2RIUndPaTh2TVRJM0xqQXVNQzR4T2pnd01EQXZJaXdpYzNWaUlqb2lhSFIwY0Rvdkx6RXlOeTR3TGpBdU1UbzRNREF3TDI5cFpHTXZiM0F2SWl3aWFXRjBJam94TmpVd056STRPRFEzTENKcFpDSTZJbWgwZEhCek9pOHZkM2QzTG5Od2FXUXVaMjkyTG1sMEwyTmxjblJwWm1sallYUnBiMjR2YjNBaUxDSnRZWEpySWpvaWFIUjBjSE02THk5M2QzY3VZV2RwWkM1bmIzWXVhWFF2ZEdobGJXVnpMMk4xYzNSdmJTOWhaMmxrTDJ4dloyOHVjM1puSWl3aWNtVm1Jam9pYUhSMGNITTZMeTlrYjJOekxtbDBZV3hwWVM1cGRDOXBkR0ZzYVdFdmMzQnBaQzl6Y0dsa0xYSmxaMjlzWlMxMFpXTnVhV05vWlMxdmFXUmpMMmwwTDNOMFlXSnBiR1V2YVc1a1pYZ3VhSFJ0YkNKOS5USHk5WWJ1Q0w0aTJUWEMyQUQtRGJqQTdQUzRqOWJFVHd1eFl6QjluV2FmSUZtV3NEeG5kSkxJNnIyZ2ZnVTVWdUJFaTRQU3ZMamh3cUtpQ2NTcnR3UkI0U2d2WnhuM2kteHZSMXFFeUJTOTZCTjgwYml6MW1BdFNwLXk3NlFvU2FDYl9xb2k1cVdHUnctMHMyVVdPUWlnLTBiZ0tJWEgzS3J0OTB5N2U2NjVsR1NnMWU3cDMzenNOSWVDcGN0N3JiNV9rUEU5N21sTkdVX2F4SHljVXNGYXg4MzlUaFZNREM0MFlfLVg4S1ZFcDNYWWwzYUlrdmxRVjgwQ2t5Q1NHY29LR0llYldXWVhLV3dhRGJfY19HS0FaQWJFTTItZldQYlpSakp4STFpVDZjd3FaVUk5elVoMzhHWm1nSmtNLTlSWE1rSGV1SktxZUFfRUJvUl92bEEifV19.hz3VNTBPEq08hstWh8KwBhNP9OnwWlS6pn-NXXG64O8FvmXsUJ8XNVmPeLyV9QtPwbSMxXs3ZZYOjvzR7fNAeCLHTQx04r7Is-tdFnAPvsN68qMbWeVtmOPS78vyLdqz4-eDA6YN49xgiCs5XHO5pyrJwU6CcznPKSJAFp40042poX8h7BU4Yx9QXKd3DedwoPfI_3pOLP53zUj4qimRJRt-3BENRu_vmFb-M4MF66ihF2raZlgs9ujn9xQ4fmpPuNQk2nxJ1cgco-5h9NYlTP8lw8cOoPKNiDp5obAf0XOmFmoxJ2Rm1RMjBpYvVDwwXO0yxZvHCJ3Zg5CPQrxxrQ"
        \\    ]
        \\  ]
        \\}
    ;

    const cs = try std.json.parseFromSliceLeaky(ClaimSet, a, x, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer cs.deinit(a);
}
