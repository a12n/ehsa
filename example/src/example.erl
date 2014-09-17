-module(example).

%% API
-export([start/0, stop/0]).

%%%===================================================================
%%% API
%%%===================================================================

start() ->
    application:ensure_all_started(example).

stop() ->
    application:stop(example).
