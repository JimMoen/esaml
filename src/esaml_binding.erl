%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc SAML HTTP binding handlers
-module(esaml_binding).

-export([decode_response/2, encode_http_redirect/3, encode_http_redirect/5, encode_http_post/3]).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-define(deflate, <<"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE">>).
-define(XML_PROLOG, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>").

-type uri() :: binary() | string().
-type hex_uri() :: string() | binary().
-type html_doc() :: binary().
-type xml() :: #xmlElement{} | #xmlDocument{}.

%% @private
-spec xml_payload_type(xml()) -> binary().
xml_payload_type(Xml) ->
    case Xml of
        #xmlDocument{content = [#xmlElement{name = Atom}]} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        #xmlElement{name = Atom} ->
            case lists:suffix("Response", atom_to_list(Atom)) of
                true -> <<"SAMLResponse">>;
                _ -> <<"SAMLRequest">>
            end;
        _ -> <<"SAMLRequest">>
    end.

%% @doc Unpack and parse a SAMLResponse with given encoding
-spec decode_response(SAMLEncoding :: binary(), SAMLResponse :: binary()) -> #xmlDocument{}.
decode_response(?deflate, SAMLResponse) ->
	XmlData = binary_to_list(zlib:unzip(base64:decode(SAMLResponse))),
	{Xml, _} = xmerl_scan:string(XmlData, [{namespace_conformant, true}]),
    Xml;
decode_response(_, SAMLResponse) ->
	Data = base64:decode(SAMLResponse),
    XmlData = case (catch zlib:unzip(Data)) of
        {'EXIT', _} -> binary_to_list(Data);
        Bin -> binary_to_list(Bin)
    end,
	{Xml, _} = xmerl_scan:string(XmlData, [{namespace_conformant, true}]),
    Xml.

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-REDIRECT binding
%%
%% Returns the URI that should be the target of redirection.
-spec encode_http_redirect(IDPTarget :: uri(), SignedXml :: xml(), RelayState :: binary()) -> uri().
encode_http_redirect(IdpTarget, SignedXml, RelayState) ->
    Type = xml_payload_type(SignedXml),
	Req = lists:flatten(xmerl:export([SignedXml], xmerl_xml, [{prolog, ?XML_PROLOG}])),
    Param = uri_encode(base64:encode_to_string(zlib:zip(Req))),
    RelayStateEsc = uri_encode(binary_to_list(RelayState)),
    FirstParamDelimiter = case lists:member($?, IdpTarget) of true -> "&"; false -> "?" end,
    iolist_to_binary([IdpTarget, FirstParamDelimiter, "SAMLEncoding=", ?deflate, "&", Type, "=", Param, "&RelayState=", RelayStateEsc]).

%% @doc Encode a SAMLRequest (or SAMLResponse) as a signed HTTP-REDIRECT binding
%%
%% For HTTP-Redirect binding, signatures are NOT embedded in the XML.
%% Instead, the signature is computed over the URL query string and
%% added as SigAlg and Signature parameters.
%%
%% Parameters:
%% - IDPTarget: The IdP URL to redirect to
%% - Xml: The SAML XML element (WITHOUT signature - use xmerl_dsig:strip/1 if needed)
%% - RelayState: The relay state value
%% - PrivateKey: RSA private key for signing
%% - SigAlg: Signature algorithm - rsa_sha1 or rsa_sha256
%%
%% Returns the complete URI with SAMLRequest, RelayState, SigAlg, and Signature.
-spec encode_http_redirect(IDPTarget :: uri(), Xml :: xml(), RelayState :: binary(),
                           PrivateKey :: #'RSAPrivateKey'{}, SigAlg :: rsa_sha1 | rsa_sha256) -> uri().
encode_http_redirect(IdpTarget, Xml, RelayState, PrivateKey, SigAlg) ->
    % Strip any existing signature from XML
    StrippedXml = xmerl_dsig:strip(Xml),
    Type = xml_payload_type(StrippedXml),
    % Serialize XML without signature
    XmlStr = lists:flatten(xmerl:export([StrippedXml], xmerl_xml, [{prolog, ?XML_PROLOG}])),
    % Deflate and base64 encode
    Param = uri_encode(base64:encode_to_string(zlib:zip(XmlStr))),
    RelayStateEsc = uri_encode(binary_to_list(RelayState)),
    % Get signature algorithm URI
    SigAlgUri = sig_alg_uri(SigAlg),
    SigAlgEsc = uri_encode(SigAlgUri),
    % Build the string to sign (order matters per SAML spec)
    % SAMLRequest=...&RelayState=...&SigAlg=...
    StringToSign = iolist_to_binary([Type, "=", Param, "&RelayState=", RelayStateEsc, "&SigAlg=", SigAlgEsc]),
    % Sign it
    HashAlg = case SigAlg of rsa_sha1 -> sha; rsa_sha256 -> sha256 end,
    Signature = public_key:sign(StringToSign, HashAlg, PrivateKey),
    SignatureEsc = uri_encode(base64:encode_to_string(Signature)),
    % Build final URL
    FirstParamDelimiter = case lists:member($?, IdpTarget) of true -> "&"; false -> "?" end,
    iolist_to_binary([IdpTarget, FirstParamDelimiter,
                      "SAMLEncoding=", ?deflate, "&",
                      StringToSign, "&Signature=", SignatureEsc]).

%% @private
sig_alg_uri(rsa_sha1) -> "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
sig_alg_uri(rsa_sha256) -> "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".

%% @doc Encode a SAMLRequest (or SAMLResponse) as an HTTP-POST binding
%%
%% Returns the HTML document to be sent to the browser, containing a
%% form and javascript to automatically submit it.
-spec encode_http_post(IDPTarget :: uri(), SignedXml :: xml(), RelayState :: binary()) -> html_doc().
encode_http_post(IdpTarget, SignedXml, RelayState) ->
    Type = xml_payload_type(SignedXml),
	Req = lists:flatten(xmerl:export([SignedXml], xmerl_xml, [{prolog, ?XML_PROLOG}])),
    generate_post_html(Type, IdpTarget, base64:encode(Req), RelayState).

generate_post_html(Type, Dest, Req, RelayState) ->
    iolist_to_binary([<<"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">
<html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
<head>
<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" />
<title>POST data</title>
</head>
<body onload=\"document.forms[0].submit()\">
<noscript>
<p><strong>Note:</strong> Since your browser does not support JavaScript, you must press the button below once to proceed.</p>
</noscript>
<form method=\"post\" action=\"">>,Dest,<<"\">
<input type=\"hidden\" name=\"">>,Type,<<"\" value=\"">>,Req,<<"\" />
<input type=\"hidden\" name=\"RelayState\" value=\"">>,RelayState,<<"\" />
<noscript><input type=\"submit\" value=\"Submit\" /></noscript>
</form>
</body>
</html>">>]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.

%% @doc Encode URI.
-spec uri_encode(uri()) -> hex_uri().
uri_encode(URI) when is_list(URI) ->
    lists:append([do_uri_encode(Char) || Char <- URI]);
uri_encode(URI) when is_binary(URI) ->
    << <<(do_uri_encode_binary(Char))/binary>> || <<Char>> <= URI >>.

do_uri_encode(Char) ->
    case reserved(Char) of
	    true ->
	        [ $% | integer_to_hexlist(Char)];
	    false ->
	        [Char]
    end.

do_uri_encode_binary(Char) ->
    case reserved(Char)  of
        true ->
            << $%, (integer_to_binary(Char, 16))/binary >>;
        false ->
            <<Char>>
    end.

reserved($;) -> true;
reserved($:) -> true;
reserved($@) -> true;
reserved($&) -> true;
reserved($=) -> true;
reserved($+) -> true;
reserved($,) -> true;
reserved($/) -> true;
reserved($?) -> true;
reserved($#) -> true;
reserved($[) -> true;
reserved($]) -> true;
reserved($<) -> true;
reserved($>) -> true;
reserved($\") -> true;
reserved(${) -> true;
reserved($}) -> true;
reserved($|) -> true;
reserved($\\) -> true;
reserved($') -> true;
reserved($^) -> true;
reserved($%) -> true;
reserved($\s) -> true;
reserved(_) -> false.

integer_to_hexlist(Int) ->
    integer_to_list(Int, 16).
