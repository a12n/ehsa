%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@bestmx.ru>
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
    {ok, Params} = ehsa_params_parser:parse(Str),
    %% Convert known parameter keys to atoms, ignore unknown parameters.
    lists:foldl(
      fun({Key, Value}, Ans)
            when Key =:= <<"algorithm">>;
                 Key =:= <<"cnonce">>;
                 Key =:= <<"domain">>;
                 Key =:= <<"nc">>;
                 Key =:= <<"nonce">>;
                 Key =:= <<"opaque">>;
                 Key =:= <<"qop">>;
                 Key =:= <<"realm">>;
                 Key =:= <<"response">>;
                 Key =:= <<"stale">>;
                 Key =:= <<"uri">>;
                 Key =:= <<"username">> ->
              [{binary_to_atom(Key, latin1), Value} | Ans];
         (_Param, Ans) ->
              Ans
      end, _Ans = [], Params).

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

parse_1_test_() ->
    [ ?_assertEqual([ {algorithm, <<"MD5">>},
                      {nc, <<"0000001f">>},
                      {qop, <<"auth-int">>},
                      {realm, <<"xyz^12:/">>} ],
                    lists:sort(
                      parse(<<"    realm=\"xyz^12:/\", \t algorithm=MD5   \t, qop=auth-int \t \t, nc=0000001f">>))),
      ?_assertEqual([ {algorithm, <<"MD5-sess">>},
                      {qop, <<"auth">>},
                      {response, <<"0123456789abcDef0123456789AbCdEf">>},
                      {uri, <<"/a/b/c">>} ],
                    lists:sort(
                      parse(<<" algorithm=MD5-sess, qop=auth, response=\"0123456789abcDef0123456789AbCdEf\", uri=\"/a/b/c\"">>))),
      ?_assertEqual([
                     {cnonce, <<"0a4f113b">>},
                     {nc, <<"00000001">>},
                     {nonce, <<"dcd98b7102dd2f0e8b11d0f600bfb0c093">>},
                     {opaque, <<"5ccc069c403ebaf9f0171e9517f40e41">>},
                     {qop, <<"auth">>},
                     {realm, <<"testrealm@host.com">>},
                     {response, <<"6629fae49393a05397450978507c4ef1">>},
                     {uri, <<"/dir/index.html">>},
                     {username, <<"Mufasa">>} ],
                    lists:sort(
                      parse(<<"username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>)))
    ].

-endif.
