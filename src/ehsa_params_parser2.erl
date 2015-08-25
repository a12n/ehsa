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

valid_param(_Pair) ->
    %% TODO: check "nc"
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
                                                      auth_params(Bytes4, [{Key, Value} | Accum], Fun)
                                              end
                                             )
                                    end
                                   );
                             (Bytes3) ->
                                  Fun(Bytes3, [{Key, Value} | Accum])
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
       Char >= $a, Char =< $z;
       Char =:= $-; Char =:= $!; Char =:= $#; Char =:= $$;
       Char =:= $%; Char =:= $&; Char =:= $´; Char =:= $*;
       Char =:= $+; Char =:= $^; Char =:= $_; Char =:= $`;
       Char =:= $|; Char =:= $~ ->
    token(Other, <<Accum/bytes, Char>>, Fun);

%% Make tokens lower case
token(<<Char, Other/bytes>>, Accum, Fun)
  when Char >= $A, Char =< $Z ->
    LowerChar = string:to_lower(Char),
    token(Other, <<Accum/bytes, LowerChar>>, Fun);

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
