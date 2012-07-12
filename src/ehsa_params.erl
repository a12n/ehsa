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
    %% TODO
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
