%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@bestmx.ru>
%%% @doc
%%% Authentication information parameters parsing.
%%% @end
%%% For copyright notice see LICENSE.
%%%-------------------------------------------------------------------
-module(ehsa_params_parser2).

%% API
-export([parse/1]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec parse(binary()) -> {ok, [{binary(), binary()}]} |
                         {error, badarg}.

parse(Bytes) ->
    spaces(
      Bytes,
      fun(Bytes1) ->
              auth_params(
                Bytes1,
                _Ans = [],
                fun(Bytes2, Ans) ->
                        whitespaces(
                          Bytes2,
                          fun(<<>>) ->
                                  case lists:all(fun valid_param/1, Ans) of
                                      true ->
                                          {ok, Ans};
                                      false ->
                                          {error, badarg}
                                  end;
                             (_Bytes3) ->
                                  {error, badarg}
                          end
                         )
                end
               )
      end
     ).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec valid_param({binary(), binary()}) -> boolean().

valid_param({<<"nc">>, Value}) ->
    try
        binary_to_integer(Value, 16),
        byte_size(Value) =:= 8
    catch
        error : badarg ->
            false
    end;

valid_param(_Param) ->
    true.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% TODO: Ignore bad white spaces around $=.
auth_param(Bytes, Fun) ->
    token(
      Bytes,
      fun(<<$=, $", Bytes1/bytes>>, Key) when byte_size(Key) > 0 ->
              quoted_string(
                Bytes1,
                fun(Bytes2, Value) ->
                        Fun(Bytes2, Key, Value)
                end
               );
         (<<$=, Bytes1/bytes>>, Key) when byte_size(Key) > 0 ->
              token(
                Bytes1,
                fun(Bytes2, Value) ->
                        Fun(Bytes2, Key, Value)
                end
               );
         (_Bytes1, _Key) ->
              {error, badarg}
      end
     ).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
auth_params(Bytes, Accum, Fun) ->
    auth_param(
      Bytes,
      fun(Bytes1, Key, Value) ->
              newline(
                Bytes1,
                fun(Bytes2) ->
                        whitespaces(
                          Bytes2,
                          fun(<<$,, Other/bytes>>) ->
                                  newline(
                                    Other,
                                    fun(Bytes3) ->
                                            whitespaces(
                                              Bytes3,
                                              fun(Bytes4) ->
                                                      Key2 = ehsa_binary:to_lower(Key),
                                                      auth_params(Bytes4, [{Key2, Value} | Accum], Fun)
                                              end
                                             )
                                    end
                                   );
                             (Bytes3) ->
                                  Key2 = ehsa_binary:to_lower(Key),
                                  Fun(Bytes3, [{Key2, Value} | Accum])
                          end
                         )
                end
               )
      end
     ).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
newline(<<$\r, $\n, Other/bytes>>, Fun) ->
    Fun(Other);

newline(Bytes, Fun) ->
    Fun(Bytes).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
spaces(<<$\s, Other/bytes>>, Fun) ->
    spaces(Other, Fun);

spaces(Bytes, Fun) ->
    Fun(Bytes).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
quoted_string(Bytes, Fun) ->
    quoted_string(Bytes, _Accum = <<>>, Fun).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
quoted_string(<<$\\, Char, Other/bytes>>, Accum, Fun)
  when Char =:= $\\; Char =:= $\" ->
    quoted_string(Other, <<Accum/bytes, Char>>, Fun);

quoted_string(<<$", Other/bytes>>, Accum, Fun) ->
    Fun(Other, Accum);

quoted_string(<<Char, Other/bytes>>, Accum, Fun) ->
    quoted_string(Other, <<Accum/bytes, Char>>, Fun);

quoted_string(_Bytes, _Accum, _Fun) ->
    {error, badarg}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
token(Bytes, Fun) ->
    token(Bytes, _Accum = <<>>, Fun).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
token(<<Char, Other/bytes>>, Accum, Fun)
  when Char >= $0, Char =< $9;
       Char >= $A, Char =< $Z;
       Char >= $a, Char =< $z;
       Char =:= $-; Char =:= $!; Char =:= $#; Char =:= $$;
       Char =:= $%; Char =:= $&; Char =:= $´; Char =:= $*;
       Char =:= $+; Char =:= $^; Char =:= $_; Char =:= $`;
       Char =:= $|; Char =:= $~ ->
    token(Other, <<Accum/bytes, Char>>, Fun);

token(Bytes, Accum, Fun) ->
    Fun(Bytes, Accum).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
whitespaces(<<Char, Other/bytes>>, Fun)
  when Char =:= $\t; Char =:= $\s ->
    whitespaces(Other, Fun);

whitespaces(Bytes, Fun) ->
    Fun(Bytes).

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

parse_1_test_() ->
    [ ?_assertEqual({error, badarg}, parse(<<"">>)),
      ?_assertEqual({error, badarg}, parse(<<" ">>)),
      ?_assertEqual({error, badarg}, parse(<<",">>)),
      ?_assertEqual({error, badarg}, parse(<<"\"">>)),
      ?_assertEqual({error, badarg}, parse(<<"a=\"">>)),
      ?_assertEqual({error, badarg}, parse(<<", a=2">>)),
      ?_assertEqual({error, badarg}, parse(<<"a=2, ">>)),
      ?_assertEqual({ok, [{<<"a">>, <<"">>}]}, parse(<<" a= ">>)),
      ?_assertEqual({ok, [{<<"a">>, <<" ">>}]}, parse(<<" a=\" \" ">>)),
      ?_assertEqual({ok, [{<<"a">>, <<"\"">>}]}, parse(<<" a=\"\\\"\" ">>)),
      ?_assertEqual({ok, [{<<"a">>, <<"\\">>}]}, parse(<<" a=\"\\\\\" ">>)),
      ?_assertEqual({ok, [{<<"a">>, <<",">>}]}, parse(<<" a=\",\" ">>)),
      ?_assertEqual({ok, [{<<"realm">>, <<"SeRvEr">>}]}, parse(<<" rEaLm=SeRvEr ">>)),
      ?_assertEqual({ok, [{<<"realm">>, <<"SeRvEr">>}]}, parse(<<" rEaLm=\"SeRvEr\" ">>)),
      fun() ->
              {ok, Ans} =
                  parse(<<"    realm=\"xyz^12:/\", \t algorithm=MD5   \t, qop=auth-int \t \t, nc=0000001f">>),
              ?assertEqual([ {<<"algorithm">>, <<"MD5">>},
                             {<<"nc">>, <<"0000001f">>},
                             {<<"qop">>, <<"auth-int">>},
                             {<<"realm">>, <<"xyz^12:/">>} ],
                           lists:sort(Ans))
      end,
      fun() ->
              {ok, Ans} =
                  parse(<<"username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>),
              ?assertEqual([ {<<"cnonce">>, <<"0a4f113b">>},
                             {<<"nc">>, <<"00000001">>},
                             {<<"nonce">>, <<"dcd98b7102dd2f0e8b11d0f600bfb0c093">>},
                             {<<"opaque">>, <<"5ccc069c403ebaf9f0171e9517f40e41">>},
                             {<<"qop">>, <<"auth">>},
                             {<<"realm">>, <<"testrealm@host.com">>},
                             {<<"response">>, <<"6629fae49393a05397450978507c4ef1">>},
                             {<<"uri">>, <<"/dir/index.html">>},
                             {<<"username">>, <<"Mufasa">>} ],
                           lists:sort(Ans))
      end,
      ?_assertEqual({error, badarg}, parse(<<"nc=xyz">>)),
      ?_assertEqual({error, badarg}, parse(<<"nc=DEADBEEF2">>)),
      ?_assertEqual({ok, [{<<"nc">>, <<"DEADBEEF">>}]}, parse(<<"nc=DEADBEEF">>))
    ].

-endif.
