-module(example_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%%===================================================================
%%% Application callbacks
%%%===================================================================

start(_Start_Type, _Start_Args) ->
    example_sup:start_link().

stop(_State) ->
    ok.
