%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @doc
%%% Nonce counter tracking for digest authentication.
%%% @end
%%% For copyright notice see LICENSE.
%%%-------------------------------------------------------------------
-module(ehsa_nc).

-behaviour(gen_server).

%% API
-export([child_spec/0, child_spec/1, start_link/1]).

%% API
-export([create/0, verify/2]).

%% gen_server callbacks
-export([code_change/3, handle_call/3, handle_cast/2, handle_info/2,
         init/1, terminate/2]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @equiv child_spec(_Options = [])
%% @end
%%--------------------------------------------------------------------
-spec child_spec() -> supervisior:child_spec().

child_spec() ->
    child_spec([]).

%%--------------------------------------------------------------------
%% @doc
%% Child specification for the supervisior of user's application.
%%
%% The available options are:
%% <dl>
%% <dt>`{max_nc, N :: pos_integer()}'</dt>
%% <dd>No more than `N' requests are allowed with the given
%% nonce. Default value is `16#ffffffff'.</dd>
%% <dt>`{nc_ttl, N :: pos_integer()}'</dt>
%% <dd>Nonce will be invalid after `N' seconds. Default value is 30
%% seconds.</dd>
%% </dl>
%% @end
%%--------------------------------------------------------------------
-spec child_spec(ehsa:options()) -> supervisior:child_spec().

child_spec(Options) ->
    {ehsa_nc, {ehsa_nc, start_link, [Options]},
     permanent, 5000, worker, [ehsa_nc]}.

%%--------------------------------------------------------------------
%% @doc
%% Start supervised nonce counting server. For allowed `Options' see
%% documentation for child_spec/1. The process will be registered as
%% `{@module}'.
%% @end
%%--------------------------------------------------------------------
-spec start_link(ehsa:options()) -> {ok, pid()} | ignore | {error, term()}.

start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Options, []).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Creates random nonce and inserts it into nonce counter tracking
%% dictionary.
%% @end
%%--------------------------------------------------------------------
-spec create() -> binary().

create() ->
    Nonce = ehsa_binary:encode(crypto:rand_bytes(16)),
    ok = gen_server:call(?MODULE, {insert, Nonce}),
    Nonce.

%%--------------------------------------------------------------------
%% @doc
%% Checks that client's `NC' value is valid for the given
%% `Nonce'. Stored value is increased, so next client's valid request
%% is with `NC + 1'. Returns `ok' if the given `NC' value is valid,
%% and `badarg' if it's invalid. For a stale nonce which is no longer
%% valid `undefined' is returned.
%% @end
%%--------------------------------------------------------------------
-spec verify(binary(), integer()) -> ok | badarg | undefined.

verify(Nonce, NC) ->
    gen_server:call(?MODULE, {verify, Nonce, NC}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
code_change(_Old_Vsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
handle_call({insert, Nonce}, _From, _State = {NCs, Max, TTL}) ->
    error = dict:find(Nonce, NCs),
    Next_NCs = dict:update_counter(Nonce, 1, NCs),
    erlang:send_after(TTL, self(), {delete, Nonce}),
    {reply, ok, {Next_NCs, Max, TTL}};

handle_call({verify, Nonce, NC}, _From, _State = {NCs, Max, TTL}) ->
    {Reply, Next_NCs} =
        case dict:find(Nonce, NCs) of
            {ok, Value} when Value > Max ->
                {undefined, dict:erase(Nonce, NCs)};
            {ok, Value} when Value =:= NC ->
                {ok, dict:update_counter(Nonce, 1, NCs)};
            {ok, _Other} ->
                {badarg, NCs};
            error ->
                {undefined, NCs}
        end,
    {reply, Reply, {Next_NCs, Max, TTL}};

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
handle_cast(stop, State) ->
    {stop, normal, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
handle_info({delete, Nonce}, _State = {NCs, Max, TTL}) ->
    Next_NCs = dict:erase(Nonce, NCs),
    {noreply, {Next_NCs, Max, TTL}};

handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
init(Options) ->
    NCs = dict:new(),
    Max = proplists:get_value(max_nc, Options, 16#ffffffff),
    TTL = proplists:get_value(nc_ttl, Options, 300),
    {ok, {NCs, Max, 1000 * TTL}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

verify_2_test_() ->
    [ fun() ->
              {ok, _Pid} = start_link([{nc_ttl, 3}]),
              Nonce = create(),
              true = is_binary(Nonce),
              ok = verify(Nonce, 1),
              badarg = verify(Nonce, 1),
              ok = verify(Nonce, 2),
              timer:sleep(3500),
              undefined = verify(Nonce, 3),
              undefined = verify(Nonce, 2),
              gen_server:cast(?MODULE, stop)
      end,
      fun() ->
              {ok, _Pid} = start_link([{max_nc, 5}]),
              Nonce = create(),
              true = is_binary(Nonce),
              badarg = verify(Nonce, 0),
              ok = verify(Nonce, 1),
              ok = verify(Nonce, 2),
              ok = verify(Nonce, 3),
              ok = verify(Nonce, 4),
              ok = verify(Nonce, 5),
              undefined = verify(Nonce, 6),
              undefined = verify(Nonce, 5),
              gen_server:cast(?MODULE, stop)
      end ].

-endif.
