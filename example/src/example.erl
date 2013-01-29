-module(example).

%% API
-export([start/0, stop/0]).

%%%===================================================================
%%% API
%%%===================================================================

start() ->
    application:start(cowboy),
    application:start(ehsa),
    application:start(example).

stop() ->
    application:stop(example),
    application:stop(ehsa),
    application:stop(cowboy).
