An implementation of the Security Assertion Markup Language (SAML) in Erlang. So far this supports enough of the standard to act as a Service Provider (SP) to perform authentication with SAML. It has been tested extensively against the SimpleSAMLPHP IdP and can be used in production.

### Supported protocols

The SAML standard refers to a flow of request/responses that make up one concrete action as a "protocol". Currently all of the basic Single-Sign-On and Single-Logout protocols are supported. There is no support at present for the optional Artifact Resolution, NameID Management, or NameID Mapping protocols.

Future work may add support for the Assertion Query protocol (which is useful to check if SSO is already available for a user without demanding they authenticate immediately).

Single sign-on protocols:

 * SP: send AuthnRequest (REDIRECT or POST) -> receive Response + Assertion (POST)

Single log-out protocols:

 * SP: send LogoutRequest (REDIRECT) -> receive LogoutResponse (REDIRECT or POST)
 * SP: receive LogoutRequest (REDIRECT OR POST) -> send LogoutResponse (REDIRECT)

esaml supports RSA+SHA1/SHA256 signing of all SP payloads, and validates signatures on all IdP responses. Compatibility flags are available to disable verification where IdP implementations lack support (see the [esaml_sp record](http://arekinath.github.io/esaml/esaml.html#type-sp), and members such as `idp_signs_logout_requests`).

### API documentation

Edoc documentation for the whole API is available at:

http://arekinath.github.io/esaml/

### Licensing

2-clause BSD

### Getting started

The simplest way to use esaml in your app is with the `esaml_cowboy` module. There is an example under `examples/sp` that shows how to make a simple SAML SP in this way.

Each of the protocols you wish to support will normally require at least one distinct URL endpoint, plus one additional URL for the SAML SP metadata. In the `sp` example, only one protocol is used: the single-sign-on SP AuthnRequest -> Response + Assertion protocol.

The typical approach is to use a single Cowboy route for all SAML endpoints:

```erlang
Dispatch = cowboy_router:compile([
    {'_', [
        {"/saml/:operation", sp_handler, []}
    ]}
])
```

Then, based on the value of the `operation` binding, you can decide which protocol to proceed with, by matching these up with the URIs you supply to `esaml_sp:setup/1`.

```erlang
init(_Transport, Req, _Args) ->
    ...
    SP = esaml_sp:setup(#esaml_sp{
        consume_uri = Base ++ "/consume",
        metadata_uri = Base ++ "/metadata",
        ...
    }),
    ...

handle(Req, S = #state{}) ->
    {Operation, Req2} = cowboy_req:binding(operation, Req),
    {Method, Req3} = cowboy_req:method(Req2),
    handle(Method, Operation, Req3, S).

handle(<<"GET">>, <<"metadata">>, Req, S) ->
    ...

handle(<<"POST">>, <<"consume">>, Req, S) ->
    ...
```

The functions on the `esaml_cowboy` module can either parse and validate an incoming SAML payload, or generate one and reply to the request with it.

For example, the way the metadata endpoint is handled in the example is to unconditionally call `esaml_cowboy:reply_with_metadata/2`, which generates the SP metadata and replies to the request:

```erlang
handle(<<"GET">>, <<"metadata">>, Req, S = #state{sp = SP}) ->
    {ok, Req2} = esaml_cowboy:reply_with_metadata(SP, Req),
    {ok, Req2, S};
```

On the other hand, the consumer endpoint (which handles the second step in the SSO protocol, receiving the Response + Assertion from the IdP) has to validate its payload before replying:

```erlang
handle(<<"POST">>, <<"consume">>, Req, S = #state{sp = SP}) ->
    case esaml_cowboy:validate_assertion(SP, Req) of
        {ok, Assertion, RelayState, Req2} ->
            % authentication success!
            ...;

        {error, Reason, Req2} ->
            {ok, Req3} = cowboy_req:reply(403, [{<<"content-type">>, <<"text/plain">>}],
                ["Access denied, assertion failed validation\n"], Req2),
            {ok, Req3, S}
    end;
```

More complex configurations, including multiple IdPs, dynamic retrieval of IdP metadata, and integration with many kinds of application authentication systems are possible.

The second esaml example, `sp_with_logout` demonstrates the addition endpoints necessary to enable Single Log-out protocol support. It also shows how you can build a bridge from esaml to local application session storage, by generating session cookies for each user that logs in (and storing them in ETS).

### Certificate Fingerprint Verification

esaml validates XML signatures on all IdP responses using the X.509 certificate embedded in the signature. For production use, you should configure trusted certificate fingerprints to prevent man-in-the-middle attacks.

#### What are Certificate Fingerprints?

A certificate fingerprint is a **cryptographic hash** (SHA-1, SHA-256, etc.) of the DER-encoded certificate. It acts as a unique identifier for the certificate and is much shorter than the full certificate.

**Important:** Fingerprints are **hashes of certificates**, not the certificates themselves. You cannot pass raw certificate binaries - they must be hashed first.

#### Obtaining Certificate Fingerprints

To get the fingerprint of your IdP's certificate:

```bash
# From a PEM certificate file
openssl x509 -in idp_cert.pem -outform DER | openssl dgst -sha256 -binary | base64

# From a certificate in the IdP metadata
# Extract the certificate and decode it first, then hash it
```

#### Configuring Trusted Fingerprints

The `trusted_fingerprints` field in `#esaml_sp{}` accepts certificate hashes in multiple formats. When you call `esaml_sp:setup/1`, it automatically converts them using `esaml_util:convert_fingerprints/1`.

**Supported formats:**

```erlang
SP = esaml_sp:setup(#esaml_sp{
    % ... other config ...
    trusted_fingerprints = [
        % 1. Raw binary hash
        % - 16 bytes for MD5
        % - 20 bytes for SHA-1
        % - 32 bytes for SHA-256
        % - 48 bytes for SHA-384
        % - 64 bytes for SHA-512
        <<198,86,10,182,119,241,20,3,198,88,35,42,145,76,251,113,52,21,246,156>>,

        % 2. Hex string with colons (will be converted to binary)
        "c6:56:0a:b6:77:f1:14:03:c6:58:23:2a:91:4c:fb:71:34:15:f6:9c",

        % 3. Tagged base64 (will be converted to {algorithm, binary()} tuple)
        "SHA256:base64encodedfingerprint==",
        "SHA1:base64encodedfingerprint==",
        "SHA384:base64encodedfingerprint==",
        "SHA512:base64encodedfingerprint==",
        "MD5:base64encodedfingerprint=="
    ]
}).
```

After `setup/1`, these are normalized to one of these formats for internal use:
- Raw binary: `<<198,86,10,...>>`
- Tagged tuple: `{md5, <<...>>}`, `{sha, <<...>>}`, `{sha256, <<...>>}`, `{sha384, <<...>>}`, or `{sha512, <<...>>}`

**To compute a fingerprint:**

```erlang
% Extract certificate from IdP metadata or response
CertBin = base64:decode(CertBase64),

% Compute SHA-256 fingerprint (recommended)
Fingerprint = crypto:hash(sha256, CertBin),

% Or other algorithms:
% FingerprintSha1   = crypto:hash(sha, CertBin),      % SHA-1 (20 bytes)
% FingerprintSha384 = crypto:hash(sha384, CertBin),   % SHA-384 (48 bytes)
% FingerprintSha512 = crypto:hash(sha512, CertBin),   % SHA-512 (64 bytes)
% FingerprintMd5    = crypto:hash(md5, CertBin).      % MD5 (16 bytes, not recommended)
```

**Using OpenSSL to get fingerprints:**

```bash
# Get hex string with colons (can be used directly in trusted_fingerprints)
openssl x509 -in idp_cert.pem -outform DER | openssl dgst -sha256 | cut -d' ' -f2 | sed 's/\(..\)/\1:/g;s/:$//'

# Or get as Erlang binary format
openssl x509 -in idp_cert.pem -outform DER | openssl dgst -sha256 -binary | xxd -p -c 256
```

#### Development vs Production

During development, you can skip fingerprint verification:

```erlang
% WARNING: Only for development! Accepts any valid certificate
SP = esaml_sp:setup(#esaml_sp{
    trusted_fingerprints = []  % Empty list skips fingerprint check
}).
```

In production, **always configure trusted fingerprints** to ensure you only accept signatures from your trusted IdP.

#### Verification Process

When verifying a signature, esaml:

1. Extracts the X.509 certificate from the XML signature
2. Determines which hash algorithms are needed based on your `trusted_fingerprints` list
3. Computes **only the required hashes** (minimizing unnecessary cryptographic operations)
4. Checks if any computed hash matches the trusted fingerprints:
   - Raw binary hashes: MD5 (16 bytes), SHA-1 (20 bytes), SHA-256 (32 bytes), SHA-384 (48 bytes), SHA-512 (64 bytes)
   - Tagged hashes: `{md5, <<...>>}`, `{sha, <<...>>}`, `{sha256, <<...>>}`, `{sha384, <<...>>}`, `{sha512, <<...>>}`

If no match is found (and the fingerprints list is not empty), verification fails with `{error, cert_not_accepted}`.

### More advanced usage

You can also tap straight into lower-level APIs in esaml if `esaml_cowboy` doesn't meet your needs. The `esaml_binding` and `esaml_sp` modules are the interface used by `esaml_cowboy` itself, and contain all the basic primitives to generate and parse SAML payloads.

This is particularly useful if you want to implement SOAP endpoints using SAML.

### Contributions

Pull requests are always welcome for bug fixes and improvements. Fixes that enable compatibility with different IdP implementations are usually welcome, but please ensure they do not come at the expense of compatibility with another IdP. esaml prefers to follow as closely to the SAML standards as possible.

Bugs/issues opened without patches are also welcome, but might take a lot longer to be looked at. ;)
