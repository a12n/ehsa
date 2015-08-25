-module(example_app).

-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

%%%===================================================================
%%% Application callbacks
%%%===================================================================

start(_StartType, _StartArgs) ->
    Dispatch = cowboy_router:compile([{'_', [ {[<<"/basic">>], example_basic_cowboy_res, []},
                                              {[<<"/digest">>], example_digest_cowboy_res, []},
                                              {[<<"/digest_int">>], example_digest_int_cowboy_res, []} ]}]),

    {ok, _Pid} = cowboy:start_http(example_server, 10,
                                   [{ip, {127,0,0,1}},
                                    {port, 8000}],
                                   [{env, [{dispatch, Dispatch}]}]),

    example_sup:start_link().

stop(_State) ->
    ok.
