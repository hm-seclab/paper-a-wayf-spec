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

const root = @import("client.zig");

const openssl = @cImport({
    @cInclude("openssl/pem.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/bio.h");
    @cInclude("openssl/evp.h");
});

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
    pub const Alg = enum { ES256, RS256 };

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
        e: ?[]const u8 = null,
        n: ?[]const u8 = null,

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
            const alg = if (self.alg) |alg| blk1: {
                break :blk1 alg;
            } else if (options.hint) |h| blk2: {
                break :blk2 h;
            } else {
                return error.UnknownAlg;
            };

            if (std.mem.eql(u8, "EC", self.kty)) {
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
            } else if (std.mem.eql(u8, "RSA", self.kty)) {
                if (std.mem.eql(u8, alg, "RS256")) {
                    if (root.verbose)
                        std.log.info("    RS256 signature verification", .{});
                    var rsa: ?*openssl.RSA = openssl.RSA_new();
                    if (rsa == null) return error.Rsa;
                    defer openssl.RSA_free(rsa.?);

                    var sig: [4096]u8 = undefined;
                    var e: [4096]u8 = undefined;
                    var n: [4096]u8 = undefined;
                    var e_bn: ?*openssl.BIGNUM = null;
                    var n_bn: ?*openssl.BIGNUM = null;
                    // TODO: verify both are valid

                    if (self.e) |e_| {
                        const size = try Base64Decoder.calcSizeForSlice(e_);
                        try Base64Decoder.decode(&e, e_);
                        e[size] = 0;
                        e_bn = openssl.BN_bin2bn(e[0..].ptr, @intCast(size), null);
                        if (e_bn == null) return error.RsaEbn;
                        if (root.verbose)
                            std.log.info("        e: {s}", .{e_});
                    } else {
                        return error.MissingE;
                    }

                    if (self.n) |n_| {
                        const size = try Base64Decoder.calcSizeForSlice(n_);
                        try Base64Decoder.decode(&n, n_);
                        n[size] = 0;
                        n_bn = openssl.BN_bin2bn(n[0..].ptr, @intCast(size), null);
                        if (n_bn == null) return error.RsaNbn;
                        if (root.verbose)
                            std.log.info("        n: {s}", .{n_});
                    } else {
                        return error.MissingN;
                    }

                    const sig_len = try Base64Decoder.calcSizeForSlice(s);
                    try Base64Decoder.decode(&sig, s);
                    if (root.verbose)
                        std.log.info("        s: {s}", .{s});

                    _ = openssl.RSA_set0_key(rsa.?, n_bn.?, e_bn.?, null);

                    var pkey: ?*openssl.EVP_PKEY = openssl.EVP_PKEY_new();
                    if (pkey == null or openssl.EVP_PKEY_set1_RSA(pkey.?, rsa.?) == 0) return error.RsaPkey;
                    defer openssl.EVP_PKEY_free(pkey.?);

                    var ctx: ?*openssl.EVP_MD_CTX = openssl.EVP_MD_CTX_new();
                    if (ctx == null) return error.RsaCtx;

                    if (openssl.EVP_DigestVerifyInit(ctx.?, null, openssl.EVP_sha256(), null, pkey.?) == 0) return error.RsaCtxInit;

                    //const r = openssl.RSA_verify(openssl.NID_sha256, d.ptr, @intCast(d.len), sig[0..].ptr, @intCast(sig_len), rsa.?);
                    const r = openssl.EVP_DigestVerify(ctx.?, sig[0..sig_len].ptr, @intCast(sig_len), d.ptr, @intCast(d.len));

                    switch (r) {
                        1 => return true,
                        0 => return false,
                        else => return error.RsaSignatureVerfication,
                    }
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
            if (self.e) |e| {
                a.free(e);
            }
            if (self.n) |n| {
                a.free(n);
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

/// We will only corss validate the TAs (last element in the chain) as we expect
/// the client to validate both trust chains individually before hand.
pub fn crossValidateTrustChains(tc1: TrustChain, tc2: TrustChain, a: Allocator) !void {
    var lhs: JWS = try JWS.fromSlice(tc1[tc1.len - 1], a);
    defer lhs.deinit(a);
    var rhs: JWS = try JWS.fromSlice(tc2[tc2.len - 1], a);
    defer rhs.deinit(a);

    if (!std.mem.eql(u8, lhs.payload.iss, rhs.payload.iss)) {
        return error.IssSubMismatch;
    }
    if (!std.mem.eql(u8, lhs.payload.sub, rhs.payload.sub)) {
        return error.IssSubMismatch;
    }

    outer: for (lhs.payload.jwks.keys) |key| {
        if (key.kid) |kid| {
            if (std.mem.eql(u8, kid, rhs.header.kid.?)) {
                if (root.verbose)
                    std.log.info("cross validating rhs with lhs key {s}", .{kid});
                const valid = try key.validate(rhs.sig, rhs.data, .{
                    .hint = rhs.header.alg.?,
                });

                if (!valid) {
                    return error.ValidationFailure;
                }

                break :outer;
            }
        }
    } else {
        return error.KeyMissing;
    }

    outer: for (rhs.payload.jwks.keys) |key| {
        if (key.kid) |kid| {
            if (std.mem.eql(u8, kid, lhs.header.kid.?)) {
                if (root.verbose)
                    std.log.info("cross validating lhs with rhs key {s}", .{kid});
                const valid = try key.validate(lhs.sig, lhs.data, .{
                    .hint = lhs.header.alg.?,
                });

                if (!valid) {
                    return error.ValidationFailure;
                }

                break :outer;
            }
        }
    } else {
        return error.KeyMissing;
    }
}

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
            //TODO: return error.Iat;
        }
        // Verify that exp has a value that is in the future.
        if (this.payload.exp <= epoch) {
            //TODO: return error.Exp;
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
                        if (root.verbose)
                            std.log.info("self validating EC[0] with key {s}", .{kid});
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
                    if (root.verbose)
                        std.log.info("validating EC[{d}] with key {s}", .{ i, kid });
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
                if (root.verbose)
                    std.log.info("self validating TA with key {s}", .{kid});
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
    _ = x;
    _ = a;

    //const cs = try std.json.parseFromSliceLeaky(ClaimSet, a, x, .{
    //    .allocate = .alloc_always,
    //    .ignore_unknown_fields = true,
    //});
    //defer cs.deinit(a);
}

test "rsa test #1" {
    const x =
        \\ {
        \\   "iss": "http://op.a-wayf.local:8002/oidc/op",
        \\   "sub": "http://op.a-wayf.local:8002/oidc/op",
        \\   "iat": 1709231639,
        \\   "exp": 1709233619,
        \\   "trust_marks": [],
        \\   "metadata": {
        \\     "federation_entity": {
        \\       "federation_resolve_endpoint": "http://op.a-wayf.local:8002/oidc/op/resolve",
        \\       "organization_name": "CIE OIDC identity provider",
        \\       "homepage_uri": "http://op.a-wayf.local:8002",
        \\       "policy_uri": "http://op.a-wayf.local:8002/oidc/op/en/website/legal-information",
        \\       "logo_uri": "http://op.a-wayf.local:8002/static/svg/logo-cie.svg",
        \\       "contacts": [
        \\         "tech@example.it"
        \\       ]
        \\     },
        \\     "openid_provider": {
        \\       "authorization_endpoint": "http://op.a-wayf.local:8002/oidc/op/authorization",
        \\       "revocation_endpoint": "http://op.a-wayf.local:8002/oidc/op/revocation",
        \\       "id_token_encryption_alg_values_supported": [
        \\         "RSA-OAEP"
        \\       ],
        \\       "id_token_encryption_enc_values_supported": [
        \\         "A128CBC-HS256"
        \\       ],
        \\       "token_endpoint": "http://op.a-wayf.local:8002/oidc/op/token",
        \\       "userinfo_endpoint": "http://op.a-wayf.local:8002/oidc/op/userinfo",
        \\       "introspection_endpoint": "http://op.a-wayf.local:8002/oidc/op/introspection",
        \\       "claims_parameter_supported": true,
        \\       "contacts": [
        \\         "ops@https://idp.it"
        \\       ],
        \\       "code_challenge_methods_supported": [
        \\         "S256"
        \\       ],
        \\       "client_registration_types_supported": [
        \\         "automatic"
        \\       ],
        \\       "request_authentication_methods_supported": {
        \\         "ar": [
        \\           "request_object"
        \\         ]
        \\       },
        \\       "acr_values_supported": [
        \\         "https://www.spid.gov.it/SpidL1",
        \\         "https://www.spid.gov.it/SpidL2",
        \\         "https://www.spid.gov.it/SpidL3"
        \\       ],
        \\       "claims_supported": [
        \\         "given_name",
        \\         "family_name",
        \\         "birthdate",
        \\         "gender",
        \\         "phone_number",
        \\         "https://attributes.eid.gov.it/fiscal_number",
        \\         "phone_number_verified",
        \\         "email",
        \\         "address",
        \\         "document_details",
        \\         "https://attributes.eid.gov.it/physical_phone_number"
        \\       ],
        \\       "grant_types_supported": [
        \\         "authorization_code",
        \\         "refresh_token"
        \\       ],
        \\       "id_token_signing_alg_values_supported": [
        \\         "RS256",
        \\         "ES256"
        \\       ],
        \\       "issuer": "http://op.a-wayf.local:8002/oidc/op",
        \\       "jwks_uri": "http://op.a-wayf.local:8002/oidc/op/openid_provider/jwks.json",
        \\       "signed_jwks_uri": "http://op.a-wayf.local:8002/oidc/op/openid_provider/jwks.jose",
        \\       "jwks": {
        \\         "keys": [
        \\           {
        \\             "kty": "RSA",
        \\             "use": "sig",
        \\             "e": "AQAB",
        \\             "n": "rJoSYv1stwlbM11tR9SYGIJuzqlJe2bv2N35oPRbwV_epjNWvGG2ZqEj53YFMC8AMZNFhuLa_LNwr1kLVE-jXQe8xjiLhe7DgMf1OnSzq9yAEXVo19BPBwkgJe2jp9HIgM_nfbIsUbSSkFAM2CKvGb0Bk2GvvqXZ12P-fpbVyA9hIQr6rNTqnCGx2-v4oViGG4u_3iTw7D1ZvLWmrmZOaKnDAqG3MJSdQ-2ggQ-Aiahg48si9C9D_JgnBV9tJ2eCS58ZC6kVG5sftElQVdH6e26mz464TZj5QgCwZCTsAQfIvBoXSdCKxpnvsFfrajz4q9BiXAryxIOl5fLmCFVNhw",
        \\             "kid": "Pd2N9-TZz_AWS3GFCkoYdRaXXls8YPhx_d_Ez7JwjQI"
        \\           }
        \\         ]
        \\       },
        \\       "scopes_supported": [
        \\         "openid",
        \\         "offline_access"
        \\       ],
        \\       "logo_uri": "http://op.a-wayf.local:8002/static/images/logo-cie.png",
        \\       "organization_name": "SPID OIDC identity provider",
        \\       "op_policy_uri": "http://op.a-wayf.local:8002/oidc/op/en/website/legal-information",
        \\       "request_parameter_supported": true,
        \\       "request_uri_parameter_supported": true,
        \\       "require_request_uri_registration": true,
        \\       "response_types_supported": [
        \\         "code"
        \\       ],
        \\       "response_modes_supported": [
        \\         "query",
        \\         "form_post"
        \\       ],
        \\       "subject_types_supported": [
        \\         "pairwise",
        \\         "public"
        \\       ],
        \\       "token_endpoint_auth_methods_supported": [
        \\         "private_key_jwt"
        \\       ],
        \\       "token_endpoint_auth_signing_alg_values_supported": [
        \\         "RS256",
        \\         "RS384",
        \\         "RS512",
        \\         "ES256",
        \\         "ES384",
        \\         "ES512"
        \\       ],
        \\       "userinfo_encryption_alg_values_supported": [
        \\         "RSA-OAEP",
        \\         "RSA-OAEP-256"
        \\       ],
        \\       "userinfo_encryption_enc_values_supported": [
        \\         "A128CBC-HS256",
        \\         "A192CBC-HS384",
        \\         "A256CBC-HS512",
        \\         "A128GCM",
        \\         "A192GCM",
        \\         "A256GCM"
        \\       ],
        \\       "userinfo_signing_alg_values_supported": [
        \\         "RS256",
        \\         "RS384",
        \\         "RS512",
        \\         "ES256",
        \\         "ES384",
        \\         "ES512"
        \\       ],
        \\       "request_object_encryption_alg_values_supported": [
        \\         "RSA-OAEP",
        \\         "RSA-OAEP-256"
        \\       ],
        \\       "request_object_encryption_enc_values_supported": [
        \\         "A128CBC-HS256",
        \\         "A192CBC-HS384",
        \\         "A256CBC-HS512",
        \\         "A128GCM",
        \\         "A192GCM",
        \\         "A256GCM"
        \\       ],
        \\       "request_object_signing_alg_values_supported": [
        \\         "RS256",
        \\         "RS384",
        \\         "RS512",
        \\         "ES256",
        \\         "ES384",
        \\         "ES512"
        \\       ]
        \\     }
        \\   },
        \\   "trust_chain": [
        \\     "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiWmhTb2FPZWRWT3NCdzZtMnZjbHdTV2lxcW5HZU9TdFQtZ1VjbG90XzY3dyJ9.eyJleHAiOjE3MDk0MDQ0MzksImlhdCI6MTcwOTIzMTYzOSwiaXNzIjoiaHR0cDovL29wLmEtd2F5Zi5sb2NhbDo4MDAyL29pZGMvb3AiLCJzdWIiOiJodHRwOi8vb3AuYS13YXlmLmxvY2FsOjgwMDIvb2lkYy9vcCIsImp3a3MiOnsia2V5cyI6W3sia3R5IjoiUlNBIiwiZSI6IkFRQUIiLCJuIjoidGczYUU5ZmQ2bHRYek5yaW1fNENHS1lXZkMzbnFjX3R2NFhqYXc0NzNDY3JmaXFEemVUS0hmUmZidmJxYjFEd21JNGZ2Q09pNTFFVmNtS0xuVGh6WHluQVVweVV2c3d2TDhfdXpnRFdPMVJTbUJHMUwwUkUtQ2tLaWg0a2VYaDFrdTloTnMxX1YtODJkSzVvTE9SLVZKTG5oWkNxVGhSNEhINlRxTGpqV3JyWGZzSFZSdmF1SmlsWDZGeEdiNUpGb2MyN1Z4eGRIMmM2UDJTSEM5d3VCOHRuZkc3T1NyU0QxZzJoN2xUWGJJZm03OGEwb3A2N2RfanVwemtvS29DVG16a1IyenZ3VFZWRGQ5OXZrRExZMldYbWI4aEl3RzZkUVpYWWxraHFBWUt6VHVUWjB0alZoME9ycWZEeFl0TEgzd1F6emFKT1Jld1pZcUx5QjA5UDh3Iiwia2lkIjoiWmhTb2FPZWRWT3NCdzZtMnZjbHdTV2lxcW5HZU9TdFQtZ1VjbG90XzY3dyJ9XX0sIm1ldGFkYXRhIjp7ImZlZGVyYXRpb25fZW50aXR5Ijp7ImZlZGVyYXRpb25fcmVzb2x2ZV9lbmRwb2ludCI6Imh0dHA6Ly9vcC5hLXdheWYubG9jYWw6ODAwMi9vaWRjL29wL3Jlc29sdmUiLCJvcmdhbml6YXRpb25fbmFtZSI6IkNJRSBPSURDIGlkZW50aXR5IHByb3ZpZGVyIiwiaG9tZXBhZ2VfdXJpIjoiaHR0cDovL29wLmEtd2F5Zi5sb2NhbDo4MDAyIiwicG9saWN5X3VyaSI6Imh0dHA6Ly9vcC5hLXdheWYubG9jYWw6ODAwMi9vaWRjL29wL2VuL3dlYnNpdGUvbGVnYWwtaW5mb3JtYXRpb24iLCJsb2dvX3VyaSI6Imh0dHA6Ly9vcC5hLXdheWYubG9jYWw6ODAwMi9zdGF0aWMvc3ZnL2xvZ28tY2llLnN2ZyIsImNvbnRhY3RzIjpbInRlY2hAZXhhbXBsZS5pdCJdfSwib3BlbmlkX3Byb3ZpZGVyIjp7ImF1dGhvcml6YXRpb25fZW5kcG9pbnQiOiJodHRwOi8vb3AuYS13YXlmLmxvY2FsOjgwMDIvb2lkYy9vcC9hdXRob3JpemF0aW9uIiwicmV2b2NhdGlvbl9lbmRwb2ludCI6Imh0dHA6Ly9vcC5hLXdheWYubG9jYWw6ODAwMi9vaWRjL29wL3Jldm9jYXRpb24iLCJpZF90b2tlbl9lbmNyeXB0aW9uX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTQS1PQUVQIl0sImlkX3Rva2VuX2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQiOlsiQTEyOENCQy1IUzI1NiJdLCJ0b2tlbl9lbmRwb2ludCI6Imh0dHA6Ly9vcC5hLXdheWYubG9jYWw6ODAwMi9vaWRjL29wL3Rva2VuIiwidXNlcmluZm9fZW5kcG9pbnQiOiJodHRwOi8vb3AuYS13YXlmLmxvY2FsOjgwMDIvb2lkYy9vcC91c2VyaW5mbyIsImludHJvc3BlY3Rpb25fZW5kcG9pbnQiOiJodHRwOi8vb3AuYS13YXlmLmxvY2FsOjgwMDIvb2lkYy9vcC9pbnRyb3NwZWN0aW9uIiwiY2xhaW1zX3BhcmFtZXRlcl9zdXBwb3J0ZWQiOnRydWUsImNvbnRhY3RzIjpbIm9wc0BodHRwczovL2lkcC5pdCJdLCJjb2RlX2NoYWxsZW5nZV9tZXRob2RzX3N1cHBvcnRlZCI6WyJTMjU2Il0sImNsaWVudF9yZWdpc3RyYXRpb25fdHlwZXNfc3VwcG9ydGVkIjpbImF1dG9tYXRpYyJdLCJyZXF1ZXN0X2F1dGhlbnRpY2F0aW9uX21ldGhvZHNfc3VwcG9ydGVkIjp7ImFyIjpbInJlcXVlc3Rfb2JqZWN0Il19LCJhY3JfdmFsdWVzX3N1cHBvcnRlZCI6WyJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9TcGlkTDEiLCJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9TcGlkTDIiLCJodHRwczovL3d3dy5zcGlkLmdvdi5pdC9TcGlkTDMiXSwiY2xhaW1zX3N1cHBvcnRlZCI6WyJnaXZlbl9uYW1lIiwiZmFtaWx5X25hbWUiLCJiaXJ0aGRhdGUiLCJnZW5kZXIiLCJwaG9uZV9udW1iZXIiLCJodHRwczovL2F0dHJpYnV0ZXMuZWlkLmdvdi5pdC9maXNjYWxfbnVtYmVyIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIiwiZW1haWwiLCJhZGRyZXNzIiwiZG9jdW1lbnRfZGV0YWlscyIsImh0dHBzOi8vYXR0cmlidXRlcy5laWQuZ292Lml0L3BoeXNpY2FsX3Bob25lX251bWJlciJdLCJncmFudF90eXBlc19zdXBwb3J0ZWQiOlsiYXV0aG9yaXphdGlvbl9jb2RlIiwicmVmcmVzaF90b2tlbiJdLCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTMjU2IiwiRVMyNTYiXSwiaXNzdWVyIjoiaHR0cDovL29wLmEtd2F5Zi5sb2NhbDo4MDAyL29pZGMvb3AiLCJqd2tzX3VyaSI6Imh0dHA6Ly9vcC5hLXdheWYubG9jYWw6ODAwMi9vaWRjL29wL29wZW5pZF9wcm92aWRlci9qd2tzLmpzb24iLCJzaWduZWRfandrc191cmkiOiJodHRwOi8vb3AuYS13YXlmLmxvY2FsOjgwMDIvb2lkYy9vcC9vcGVuaWRfcHJvdmlkZXIvandrcy5qb3NlIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJ1c2UiOiJzaWciLCJlIjoiQVFBQiIsIm4iOiJySm9TWXYxc3R3bGJNMTF0UjlTWUdJSnV6cWxKZTJidjJOMzVvUFJid1ZfZXBqTld2R0cyWnFFajUzWUZNQzhBTVpORmh1TGFfTE53cjFrTFZFLWpYUWU4eGppTGhlN0RnTWYxT25TenE5eUFFWFZvMTlCUEJ3a2dKZTJqcDlISWdNX25mYklzVWJTU2tGQU0yQ0t2R2IwQmsyR3Z2cVhaMTJQLWZwYlZ5QTloSVFyNnJOVHFuQ0d4Mi12NG9WaUdHNHVfM2lUdzdEMVp2TFdtcm1aT2FLbkRBcUczTUpTZFEtMmdnUS1BaWFoZzQ4c2k5QzlEX0pnbkJWOXRKMmVDUzU4WkM2a1ZHNXNmdEVsUVZkSDZlMjZtejQ2NFRaajVRZ0N3WkNUc0FRZkl2Qm9YU2RDS3hwbnZzRmZyYWp6NHE5QmlYQXJ5eElPbDVmTG1DRlZOaHciLCJraWQiOiJQZDJOOS1UWnpfQVdTM0dGQ2tvWWRSYVhYbHM4WVBoeF9kX0V6N0p3alFJIn1dfSwic2NvcGVzX3N1cHBvcnRlZCI6WyJvcGVuaWQiLCJvZmZsaW5lX2FjY2VzcyJdLCJsb2dvX3VyaSI6Imh0dHA6Ly9vcC5hLXdheWYubG9jYWw6ODAwMi9zdGF0aWMvaW1hZ2VzL2xvZ28tY2llLnBuZyIsIm9yZ2FuaXphdGlvbl9uYW1lIjoiU1BJRCBPSURDIGlkZW50aXR5IHByb3ZpZGVyIiwib3BfcG9saWN5X3VyaSI6Imh0dHA6Ly9vcC5hLXdheWYubG9jYWw6ODAwMi9vaWRjL29wL2VuL3dlYnNpdGUvbGVnYWwtaW5mb3JtYXRpb24iLCJyZXF1ZXN0X3BhcmFtZXRlcl9zdXBwb3J0ZWQiOnRydWUsInJlcXVlc3RfdXJpX3BhcmFtZXRlcl9zdXBwb3J0ZWQiOnRydWUsInJlcXVpcmVfcmVxdWVzdF91cmlfcmVnaXN0cmF0aW9uIjp0cnVlLCJyZXNwb25zZV90eXBlc19zdXBwb3J0ZWQiOlsiY29kZSJdLCJyZXNwb25zZV9tb2Rlc19zdXBwb3J0ZWQiOlsicXVlcnkiLCJmb3JtX3Bvc3QiXSwic3ViamVjdF90eXBlc19zdXBwb3J0ZWQiOlsicGFpcndpc2UiLCJwdWJsaWMiXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzX3N1cHBvcnRlZCI6WyJwcml2YXRlX2tleV9qd3QiXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTMjU2IiwiUlMzODQiLCJSUzUxMiIsIkVTMjU2IiwiRVMzODQiLCJFUzUxMiJdLCJ1c2VyaW5mb19lbmNyeXB0aW9uX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIlJTQS1PQUVQIiwiUlNBLU9BRVAtMjU2Il0sInVzZXJpbmZvX2VuY3J5cHRpb25fZW5jX3ZhbHVlc19zdXBwb3J0ZWQiOlsiQTEyOENCQy1IUzI1NiIsIkExOTJDQkMtSFMzODQiLCJBMjU2Q0JDLUhTNTEyIiwiQTEyOEdDTSIsIkExOTJHQ00iLCJBMjU2R0NNIl0sInVzZXJpbmZvX3NpZ25pbmdfYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlMyNTYiLCJSUzM4NCIsIlJTNTEyIiwiRVMyNTYiLCJFUzM4NCIsIkVTNTEyIl0sInJlcXVlc3Rfb2JqZWN0X2VuY3J5cHRpb25fYWxnX3ZhbHVlc19zdXBwb3J0ZWQiOlsiUlNBLU9BRVAiLCJSU0EtT0FFUC0yNTYiXSwicmVxdWVzdF9vYmplY3RfZW5jcnlwdGlvbl9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMTI4Q0JDLUhTMjU2IiwiQTE5MkNCQy1IUzM4NCIsIkEyNTZDQkMtSFM1MTIiLCJBMTI4R0NNIiwiQTE5MkdDTSIsIkEyNTZHQ00iXSwicmVxdWVzdF9vYmplY3Rfc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJSUzI1NiIsIlJTMzg0IiwiUlM1MTIiLCJFUzI1NiIsIkVTMzg0IiwiRVM1MTIiXX19LCJhdXRob3JpdHlfaGludHMiOlsiaHR0cDovL3RhLmEtd2F5Zi5sb2NhbDo4MDAwIl19.NXbKNgR4El3bbMyM1rhgN2wmPNTrXQ61Pzj0yAEfA5XwETzlXt-7UJdRLYWtML0GPMSISuYfXLMELHh0R7K6qiCwhXhxqx9kI5SJa4oXmEOApM5CKYDmcrOCaKLCWG1m0u9ciCtSwaA39mZxaqPpNEfqY7DXt5-pQC5SCBEhwWWo5scVBjNR0Bn-bB9fNPFINjgQ9gSRWrgwfATijHVWWH1VlB6jQC6nwjnlTjqCMjqz1I2Iwzh_2S82kFNr1W4nbDCMJMqIl_Qbs6WmSW_KL1lSHpDeG8tttKU3bBCyUchmhsaPI4_GFgoK0eJin9BpKR8qbE4ikN2skiuG1hGt4A",
        \\     "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiQlh2ZnJsbmhBTXVIUjA3YWpVbUFjQlJRY1N6bXcwY19SQWdKbnBTLTlXUSJ9.eyJleHAiOjE3MDk0MDQ0MzksImlhdCI6MTcwOTIzMTYzOSwiaXNzIjoiaHR0cDovL3RhLmEtd2F5Zi5sb2NhbDo4MDAwIiwic3ViIjoiaHR0cDovL29wLmEtd2F5Zi5sb2NhbDo4MDAyL29pZGMvb3AiLCJqd2tzIjp7ImtleXMiOlt7Imt0eSI6IlJTQSIsIm4iOiJ0ZzNhRTlmZDZsdFh6TnJpbV80Q0dLWVdmQzNucWNfdHY0WGphdzQ3M0NjcmZpcUR6ZVRLSGZSZmJ2YnFiMUR3bUk0ZnZDT2k1MUVWY21LTG5UaHpYeW5BVXB5VXZzd3ZMOF91emdEV08xUlNtQkcxTDBSRS1Da0tpaDRrZVhoMWt1OWhOczFfVi04MmRLNW9MT1ItVkpMbmhaQ3FUaFI0SEg2VHFMampXcnJYZnNIVlJ2YXVKaWxYNkZ4R2I1SkZvYzI3Vnh4ZEgyYzZQMlNIQzl3dUI4dG5mRzdPU3JTRDFnMmg3bFRYYklmbTc4YTBvcDY3ZF9qdXB6a29Lb0NUbXprUjJ6dndUVlZEZDk5dmtETFkyV1htYjhoSXdHNmRRWlhZbGtocUFZS3pUdVRaMHRqVmgwT3JxZkR4WXRMSDN3UXp6YUpPUmV3WllxTHlCMDlQOHciLCJlIjoiQVFBQiIsImtpZCI6IlpoU29hT2VkVk9zQnc2bTJ2Y2x3U1dpcXFuR2VPU3RULWdVY2xvdF82N3cifV19LCJtZXRhZGF0YV9wb2xpY3kiOnsib3BlbmlkX3Byb3ZpZGVyIjp7fX0sInNvdXJjZV9lbmRwb2ludCI6Imh0dHA6Ly90YS5hLXdheWYubG9jYWw6ODAwMC9mZXRjaCIsInRydXN0X21hcmtzIjpbeyJpZCI6Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L29wZW5pZC1mZWRlcmF0aW9uL2FncmVlbWVudC9vcC1wdWJsaWMiLCJ0cnVzdF9tYXJrIjoiZXlKMGVYQWlPaUowY25WemRDMXRZWEpySzJwM2RDSXNJbUZzWnlJNklsSlRNalUySWl3aWEybGtJam9pUWxoMlpuSnNibWhCVFhWSVVqQTNZV3BWYlVGalFsSlJZMU42Ylhjd1kxOVNRV2RLYm5CVExUbFhVU0o5LmV5SnBjM01pT2lKb2RIUndPaTh2ZEdFdVlTMTNZWGxtTG14dlkyRnNPamd3TURBaUxDSnpkV0lpT2lKb2RIUndPaTh2YjNBdVlTMTNZWGxtTG14dlkyRnNPamd3TURJdmIybGtZeTl2Y0NJc0ltbGhkQ0k2TVRjd09USXpNVFl6T1N3aWFXUWlPaUpvZEhSd2N6b3ZMM2QzZHk1emNHbGtMbWR2ZGk1cGRDOWpaWEowYVdacFkyRjBhVzl1TDI5d0lpd2liV0Z5YXlJNkltaDBkSEJ6T2k4dmQzZDNMbUZuYVdRdVoyOTJMbWwwTDNSb1pXMWxjeTlqZFhOMGIyMHZZV2RwWkM5c2IyZHZMbk4yWnlJc0luSmxaaUk2SW1oMGRIQnpPaTh2Wkc5amN5NXBkR0ZzYVdFdWFYUXZhWFJoYkdsaEwzTndhV1F2YzNCcFpDMXlaV2R2YkdVdGRHVmpibWxqYUdVdGIybGtZeTlwZEM5emRHRmlhV3hsTDJsdVpHVjRMbWgwYld3aWZRLmhlbDMtSkJvYzNpcTU5QW9EZkJBbEpwcF9KbWwweS0yMllTdEozTjJfU0d6a3YwU1l1TFp1VldqM3BhUG9aamxiUlhnVXpvQlpka2hlWDJTMGZpYlFYQ0pzMDNDSXJwWW1LV25Kd1dZdDdXN3pXWnNBRnNjWjJlQVZEcVl4RXdUSlVFbFNBV29xa1ExNWJFalN3SU02aGZCYkNuUktick9tT2V4RFZ4OHhuSFF6eVg3TDdwV1g0Y2p1NWRWaDJvcTNlbGJPT191blppVTFLWHZfSUhUOElwVzZvZ2h4VHp4aS1OVUdITXFydjFRMmw0RHhRdmtsMml3Vzc2VlRKRDVLbkV1UTk1TEVLQm9waW9BSHJuUGduVzJ6NlluU1VjT1RPTmZiMFhGMW1uUklHblVBcnIySTJfcWg1MmMzUFhZankwdHROSExlaU1GU21zUGdGMVdTZyJ9XX0.ZUIqOxr5SwnpeWwrUVJp8K-1Gu-KktuxtDHf5EeGkSdG9AFWA7RLsJ3NmSBNHRGh9mTvA6C5Msb5bUdfSHh7kCaNf3EqMEB1PXY3GY3L4kDn2D0bsc4LCklqgRSTDNwK8YeniJemTkGY2JjaJk5BfvRlH2iIYgGpiKZ0xH0J2Q3uwiBIy7VjMuI9G8gLZvtgKMgDSUjvvCDLuWgNxl6uO4hiMUDfgPGLdh8Ym_UYinl5qww9wb8-pwB3pYa4g-hYYn1VBrEATpAayHvaRRO8AP2GH9vMl8d2swaBpIvpbKTnqi4YSkmcpvSTj44Jq-AEk-Qq_gPj0bw0MRL20XwvNw",
        \\     "eyJ0eXAiOiJlbnRpdHktc3RhdGVtZW50K2p3dCIsImFsZyI6IlJTMjU2Iiwia2lkIjoiQlh2ZnJsbmhBTXVIUjA3YWpVbUFjQlJRY1N6bXcwY19SQWdKbnBTLTlXUSJ9.eyJleHAiOjE3MDkyMzM2MTksImlhdCI6MTcwOTIzMTYzOSwiaXNzIjoiaHR0cDovL3RhLmEtd2F5Zi5sb2NhbDo4MDAwIiwic3ViIjoiaHR0cDovL3RhLmEtd2F5Zi5sb2NhbDo4MDAwIiwiandrcyI6eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsIm4iOiJvOElvbFJqWmxremN0LTQ4cmhyVmxUbllVMXBrTWJWSkQtRFUwNW9NUzlSVkdyc0Z5cGc5OG0tS3c0SDRxTlB5UVZ4Mk9RT1JpLXhTaGdrN0hVLWdLXzJwVmd1WWt2MDZGYWpMX2VkRUFxcXNxdF83NFFmMldMUkM1cGZKR196OU9Qelk4Skd5ay16M1NiZUhOX0JYS0k4R1k1RTRXVTJTc3RtUTlmeUw0Q3h0UmZqVWlhOGxpbVRDXzNNT3BUM3ppNW5yMDNqZmJqcG5qZ2E1MXFYdXJ4bmx6YzNhX3hqazVSQUFwS3hVdk53aEoyNzVNMENtQjk5RGpQd0Y2Qkx2VWdKcWd5Q3BVT24zNkxPaEk0RnF1VnFocWhpd0tsTW1pTWUzeXkweU5RN0ZYQld4anpoZXhicHljM1Z1N3pGSUhQQWNDNFV5SVFoYzN3YUVqMnZpWHciLCJraWQiOiJCWHZmcmxuaEFNdUhSMDdhalVtQWNCUlFjU3ptdzBjX1JBZ0pucFMtOVdRIn1dfSwibWV0YWRhdGEiOnsiZmVkZXJhdGlvbl9lbnRpdHkiOnsiY29udGFjdHMiOlsib3BzQGxvY2FsaG9zdCJdLCJmZWRlcmF0aW9uX2ZldGNoX2VuZHBvaW50IjoiaHR0cDovL3RhLmEtd2F5Zi5sb2NhbDo4MDAwL2ZldGNoIiwiZmVkZXJhdGlvbl9yZXNvbHZlX2VuZHBvaW50IjoiaHR0cDovL3RhLmEtd2F5Zi5sb2NhbDo4MDAwL3Jlc29sdmUiLCJmZWRlcmF0aW9uX3RydXN0X21hcmtfc3RhdHVzX2VuZHBvaW50IjoiaHR0cDovL3RhLmEtd2F5Zi5sb2NhbDo4MDAwL3RydXN0X21hcmtfc3RhdHVzIiwiaG9tZXBhZ2VfdXJpIjoiaHR0cDovL3RhLmEtd2F5Zi5sb2NhbDo4MDAwIiwib3JnYW5pemF0aW9uX25hbWUiOiJleGFtcGxlIFRBIiwicG9saWN5X3VyaSI6Imh0dHA6Ly90YS5hLXdheWYubG9jYWw6ODAwMC9lbi93ZWJzaXRlL2xlZ2FsLWluZm9ybWF0aW9uIiwibG9nb191cmkiOiJodHRwOi8vdGEuYS13YXlmLmxvY2FsOjgwMDAvc3RhdGljL3N2Zy9zcGlkLWxvZ28tYy1sYi5zdmciLCJmZWRlcmF0aW9uX2xpc3RfZW5kcG9pbnQiOiJodHRwOi8vdGEuYS13YXlmLmxvY2FsOjgwMDAvbGlzdCJ9fSwidHJ1c3RfbWFya19pc3N1ZXJzIjp7Imh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAvcHVibGljIjpbImh0dHBzOi8vcmVnaXN0cnkuc3BpZC5hZ2lkLmdvdi5pdCIsImh0dHBzOi8vcHVibGljLmludGVybWVkaWFyeS5zcGlkLml0Il0sImh0dHBzOi8vd3d3LnNwaWQuZ292Lml0L2NlcnRpZmljYXRpb24vcnAvcHJpdmF0ZSI6WyJodHRwczovL3JlZ2lzdHJ5LnNwaWQuYWdpZC5nb3YuaXQiLCJodHRwczovL3ByaXZhdGUub3RoZXIuaW50ZXJtZWRpYXJ5Lml0Il0sImh0dHBzOi8vc2dkLmFhLml0L29uYm9hcmRpbmciOlsiaHR0cHM6Ly9zZ2QuYWEuaXQiXX0sImNvbnN0cmFpbnRzIjp7Im1heF9wYXRoX2xlbmd0aCI6MX19.i3aV8IrlzqnRVnfQVQDWZT5Pj5NrGuFsmTPFcINunj7zpUK6N-TE6uu4lxiGuCmaQA9cJYrEjsPEvWTyfx3C8eqRMHS6M-8tlIvuVEa0GsKh68r9A4xzWY8FvVsacL0LL1CDQwNgMiOIAY-WUvXI69Ayst317eZJrCShii7Sg2JCawDgbWalDFrXsHz6Vtqhbm7g1OzQPFK_q1E__njviTh1htxxStm9-4YJinJ981akPoBurMnV03RDTer4O6sijSDXu8WBHM85EctXKhmasVsOgzaWq9RoCRZ83Qad_hhhTZPKtusIJhgts_5r2-uw5OYvxyzff6uJl0J_NZ_Zuw"
        \\   ]
        \\ }
    ;

    const cs = try std.json.parseFromSliceLeaky(ClaimSet, std.testing.allocator, x, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    defer cs.deinit(std.testing.allocator);

    try validateTrustChain(cs.trust_chain.?, 1709232639, std.testing.allocator);
}
