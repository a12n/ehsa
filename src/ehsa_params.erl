%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%% Authentication information parameters handling.
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_params).

%% API
-export([format/1, format/2, parse/1]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec format([{atom(), binary()}]) -> binary() | iolist().
format([]) ->
    [];
format([{Key, Value}]) ->
    format(Key, Value);
format([{Key, Value} | Other]) ->
    [format(Key, Value), <<", ">>, format(Other)].

%%--------------------------------------------------------------------
%% @doc
%% Some auth parameter values must be quoted.
%% @end
%%--------------------------------------------------------------------
-spec format(atom(), binary()) -> binary() | iolist().
format(Key, Value)
  when Key =:= cnonce;
       Key =:= domain;
       Key =:= nonce;
       Key =:= opaque;
       Key =:= qop;
       Key =:= realm;
       Key =:= response;
       Key =:= uri;
       Key =:= username ->
    [atom_to_binary(Key, latin1), <<"=\"">>, Value, <<"\"">>];
format(Key, Value) ->
    [atom_to_binary(Key, latin1), <<"=">>, Value].

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec parse(binary()) -> [{atom(), binary()}].
parse(_Str) ->
    %% 1.2 Access Authentication Framework
    %% realm       = "realm" "=" realm-value
    %% realm-value = quoted-string

    %% 3.2.1 The WWW-Authenticate Response Header
    %% challenge        =  "Digest" digest-challenge
    %%
    %% digest-challenge  = 1#( realm | [ domain ] | nonce |
    %%                     [ opaque ] |[ stale ] | [ algorithm ] |
    %%                     [ qop-options ] | [auth-param] )
    %%
    %%
    %% domain            = "domain" "=" <"> URI ( 1*SP URI ) <">
    %% URI               = absoluteURI | abs_path
    %% nonce             = "nonce" "=" nonce-value
    %% nonce-value       = quoted-string
    %% opaque            = "opaque" "=" quoted-string
    %% stale             = "stale" "=" ( "true" | "false" )
    %% algorithm         = "algorithm" "=" ( "MD5" | "MD5-sess" |
    %%                      token )
    %% qop-options       = "qop" "=" <"> 1#qop-value <">
    %% qop-value         = "auth" | "auth-int" | token

    %% 3.2.2 The Authorization Request Header
    %% credentials      = "Digest" digest-response
    %% digest-response  = 1#( username | realm | nonce | digest-uri
    %%                 | response | [ algorithm ] | [cnonce] |
    %%                 [opaque] | [message-qop] |
    %%                     [nonce-count]  | [auth-param] )
    %%
    %% username         = "username" "=" username-value
    %% username-value   = quoted-string
    %% digest-uri       = "uri" "=" digest-uri-value
    %% digest-uri-value = request-uri   ; As specified by HTTP/1.1
    %% message-qop      = "qop" "=" qop-value
    %% cnonce           = "cnonce" "=" cnonce-value
    %% cnonce-value     = nonce-value
    %% nonce-count      = "nc" "=" nc-value
    %% nc-value         = 8LHEX
    %% response         = "response" "=" request-digest
    %% request-digest = <"> 32LHEX <">
    %% LHEX             =  "0" | "1" | "2" | "3" |
    %%                     "4" | "5" | "6" | "7" |
    %%                     "8" | "9" | "a" | "b" |
    %%                     "c" | "d" | "e" | "f"

    [].

%%%===================================================================
%%% Tests
%%%===================================================================

-include_lib("eunit/include/eunit.hrl").

-ifdef(TEST).

format_1_test() ->
    <<>> = iolist_to_binary(format([])),
    <<"realm=\"XYZ\"">> = iolist_to_binary(format([{realm, <<"XYZ">>}])),
    <<"qop=\"\"">> = iolist_to_binary(format([{qop, <<>>}])),
    <<"method=MD5, username=\"xyz\"">> =
        iolist_to_binary(format([{method, <<"MD5">>},
                                 {username, <<"xyz">>}])).

format_2_test() ->
    <<"realm=\"Test\"">> = iolist_to_binary(format(realm, <<"Test">>)),
    <<"qop=\"\"">> = iolist_to_binary(format(qop, <<>>)),
    <<"method=MD5">> = iolist_to_binary(format(method, <<"MD5">>)).

-endif.
