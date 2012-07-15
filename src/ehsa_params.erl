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
-spec format([{atom(), binary() | iolist()}]) -> binary() | iolist().
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
-spec format(atom(), binary() | iolist()) -> binary() | iolist().
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
parse(Str) ->
    [_ | _] = ehsa_params_parser:parse(Str).

%%%===================================================================
%%% Tests
%%%===================================================================

-include_lib("eunit/include/eunit.hrl").

-ifdef(TEST).

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
      ?_test( [{<<"a">>, <<"1">>},
               {<<"b">>, <<"c">>},
               {<<"d">>, <<"e">>}] = parse(<<"a=1\t,\tb=\"c\"\t,\td=e">>) ),
      ?_assertException(error, {badmatch, _}, parse(<<" realm ">>)),
      ?_assertException(error, {badmatch, _}, parse(<<" xyz= ">>)),
      ?_assertException(error, {badmatch, _}, parse(<<", realm=\"Foo\"">>)),
      ?_assertException(error, {badmatch, _}, parse(<<"realm=\"Foo\", ">>)) ].

-endif.
