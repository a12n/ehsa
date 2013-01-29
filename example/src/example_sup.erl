-module(example_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

%%%===================================================================
%%% API functions
%%%===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%%===================================================================
%%% Supervisor callbacks
%%%===================================================================

init([]) ->
    Cowboy = cowboy:child_spec(example_server,
                               10,
                               cowboy_tcp_transport,
                               [{ip, {127,0,0,1}},
                                {port, 8000}],
                               cowboy_http_protocol,
                               [{dispatch, [{'_', [ {[<<"basic">>], example_basic_res, []},
                                                    {[<<"digest">>], example_digest_res, []},
                                                    {[<<"digest_int">>], example_digest_int_res, []} ]}]}]),
    
    %% NC server must be running for ehsa_digest to work.
    EHSA_NC = ehsa_nc:child_spec([{max_nc, 5},
                                  {nc_ttl, 30}]),
    
    {ok, { {one_for_one, 5, 10}, [Cowboy, EHSA_NC]} }.
