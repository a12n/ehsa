%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@bestmx.ru>
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
%% <dd>Nonce will be invalid after `N' seconds. Default value is 60
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
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
handle_call({insert, Nonce}, _From, State = {NCs, _Max, TTL}) ->
    true = ets:insert_new(NCs, {Nonce, 1}),
    erlang:send_after(TTL, self(), {delete, Nonce}),
    {reply, ok, State};

handle_call({verify, Nonce, NC}, _From, State = {NCs, Max, _TTL}) ->
    Reply =
        try ets:lookup_element(NCs, Nonce, 2) of
            Value when Value > Max ->
                %% Stale nonce
                ets:delete(NCs, Nonce),
                undefined;
            Value when Value =:= NC ->
                %% Valid nonce and counter
                ets:update_counter(NCs, Nonce, 1),
                ok;
            _Other ->
                %% Invalid NC
                badarg
        catch
            error : badarg ->
                %% Invalid nonce
                undefined
        end,
    {reply, Reply, State};

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
handle_info({delete, Nonce}, State = {NCs, _Max, _TTL}) ->
    ets:delete(NCs, Nonce),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
init(Options) ->
    NCs = ets:new(?MODULE, [private]),
    Max = proplists:get_value(max_nc, Options, 16#ffffffff),
    TTL = proplists:get_value(nc_ttl, Options, 60),
    {ok, {NCs, Max, 1000 * TTL}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State = {NCs, _Max, _TTL}) ->
    ets:delete(NCs),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

ehsa_nc_test_() ->
    {setup,
     fun() -> {ok, Pid} = start_link([{max_nc, 5}, {nc_ttl, 3}]), Pid end,
     fun(Pid) -> gen_server:cast(Pid, stop) end,
     fun(Pid) ->
             [ ?_assertEqual(child_spec(), child_spec([])),
               ?_assertEqual(ok, gen_server:call(Pid, abcabcabc)),
               ?_assertEqual(ok, gen_server:cast(Pid, xyzxyzxyz)),
               ?_test(Pid ! foofoo),
               ?_assert(is_binary(create())),
               fun() ->
                       Nonce = create(),
                       ?assertEqual(ok, verify(Nonce, 1)),
                       ?assertEqual(badarg, verify(Nonce, 1)),
                       ?assertEqual(ok, verify(Nonce, 2)),
                       timer:sleep(3500),
                       ?assertEqual(undefined, verify(Nonce, 3)),
                       ?assertEqual(undefined, verify(Nonce, 2))
               end,
               fun() ->
                       Nonce = create(),
                       ?assertEqual(badarg, verify(Nonce, 0)),
                       ?assertEqual(ok, verify(Nonce, 1)),
                       ?assertEqual(ok, verify(Nonce, 2)),
                       ?assertEqual(ok, verify(Nonce, 3)),
                       ?assertEqual(ok, verify(Nonce, 4)),
                       ?assertEqual(ok, verify(Nonce, 5)),
                       ?assertEqual(undefined, verify(Nonce, 6)),
                       ?assertEqual(undefined, verify(Nonce, 5))
               end ]
     end}.

-endif.
