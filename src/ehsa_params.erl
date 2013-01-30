%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @doc
%%% Authentication information parameters handling.
%%% @end
%%% For copyright notice see LICENSE.
%%%-------------------------------------------------------------------
-module(ehsa_params).

%% API
-export([format/1, format/2, parse/1]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Formats list of authentication parameters.
%% @end
%%--------------------------------------------------------------------
-spec format([{atom(), iodata()}]) -> iodata().

format([]) ->
    [];

format([{Key, Value}]) ->
    format(Key, Value);

format([{Key, Value} | Other]) ->
    [format(Key, Value), <<", ">>, format(Other)].

%%--------------------------------------------------------------------
%% @doc
%% Formats single authentication parameter.
%% @end
%%--------------------------------------------------------------------
-spec format(atom(), iodata()) -> iodata().

format(Key, Value)
  when Key =:= cnonce;
       Key =:= comment;
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
%% Parses authentication parameters string. The result is key-value
%% pairs of the parameters.
%% @end
%%--------------------------------------------------------------------
-spec parse(binary()) -> [{atom(), binary()}].

parse(Str) ->
    [_ | _] = ehsa_params_parser:parse(Str).

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

format_1_test_() ->
    [ ?_test( <<>> = iolist_to_binary(format([])) ),
      ?_test( <<"realm=\"XYZ\"">> = iolist_to_binary(format([{realm, <<"XYZ">>}])) ),
      ?_test( <<"qop=\"\"">> = iolist_to_binary(format([{qop, <<>>}])) ),
      ?_test( <<"algorithm=MD5, username=\"xyz\"">> =
                  iolist_to_binary(format([{algorithm, <<"MD5">>},
                                           {username, <<"xyz">>}])) ) ].

format_2_test_() ->
    [ ?_test( <<"realm=\"Test\"">> = iolist_to_binary(format(realm, <<"Test">>)) ),
      ?_test( <<"qop=\"\"">> = iolist_to_binary(format(qop, <<>>)) ),
      ?_test( <<"algorithm=MD5">> = iolist_to_binary(format(algorithm, <<"MD5">>)) ) ].

%% TODO: More tests.
parse_1_test_() ->
    [ ?_test( [{realm, <<"xyz^12:/">>},
               {algorithm, <<"MD5">>},
               {qop, <<"auth-int">>},
               {nc, <<"0000001f">>}] = parse(<<"    realm=\"xyz^12:/\", \t algorithm=MD5   \t, qop=auth-int \t \t, nc=0000001f">>) ),
      ?_test( [{algorithm, <<"MD5-sess">>},
               {qop, <<"auth">>},
               {response, <<"0123456789abcDef0123456789AbCdEf">>},
               {uri, <<"/a/b/c">>}] = parse(<<" algorithm=MD5-sess, qop=auth, response=\"0123456789abcDef0123456789AbCdEf\", uri=\"/a/b/c\"">>) ),
      ?_test( [{username, <<"Mufasa">>},
               {realm, <<"testrealm@host.com">>},
               {nonce, <<"dcd98b7102dd2f0e8b11d0f600bfb0c093">>},
               {uri, <<"/dir/index.html">>},
               {qop, <<"auth">>},
               {nc, <<"00000001">>},
               {cnonce, <<"0a4f113b">>},
               {response, <<"6629fae49393a05397450978507c4ef1">>},
               {opaque, <<"5ccc069c403ebaf9f0171e9517f40e41">>}] = parse(<<"username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>) ),
      ?_test( [{<<"a">>, <<"1">>},
               {<<"b">>, <<"c">>},
               {<<"d">>, <<"e">>}] = parse(<<"a=1\t,\tb=\"c\"\t,\td=e">>) ),
      ?_assertException(error, {badmatch, _}, parse(<<" realm ">>)),
      ?_assertException(error, {badmatch, _}, parse(<<" xyz= ">>)),
      ?_assertException(error, {badmatch, _}, parse(<<", realm=\"Foo\"">>)),
      ?_assertException(error, {badmatch, _}, parse(<<"realm=\"Foo\", ">>)) ].

-endif.
