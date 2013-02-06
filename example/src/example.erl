-module(example).

%% API
-export([start/0, stop/0]).

%%%===================================================================
%%% API
%%%===================================================================

start() ->
    application:start(cowboy),

    application:start(crypto),
    application:start(inets),
    application:start(mochiweb),
    application:start(webmachine),

    application:start(ehsa),

    application:start(example).

stop() ->
    application:stop(example),

    application:stop(ehsa),

    application:stop(webmachine),
    application:stop(mochiweb),
    application:stop(inets),
    application:stop(crypto),

    application:stop(cowboy).
