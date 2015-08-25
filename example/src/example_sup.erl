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
    WebmachineArgs = [ {ip, "127.0.0.1"},
                       {port, 8001},
                       {dispatch, [ {["basic"], example_basic_webmachine_res, []},
                                    {["digest"], example_digest_webmachine_res, []},
                                    {["digest_int"], example_digest_int_webmachine_res, []} ]} ],
    Webmachine = {webmachine_mochiweb,
                  {webmachine_mochiweb, start, [WebmachineArgs]},
                  permanent, 5000, worker, dynamic},

    %% NC server must be running for ehsa_digest to work.
    NC = ehsa_nc:child_spec([{max_nc, 5},
                             {nc_ttl, 30}]),

    {ok, { {one_for_one, 5, 10}, [Webmachine, NC]} }.
