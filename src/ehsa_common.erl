%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_common).

%% API
-export([start_link/2]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec start_link(atom(), [{atom(), term()}]) ->
                        {ok, pid()} | ignore | {error, term()}.
start_link(Module, Args) ->
    case proplists:get_value(register, Args, true) of
        true ->
            gen_server:start_link({local, Module}, Module, Args, []);
        false ->
            gen_server:start_link(Module, Args, [])
    end.
