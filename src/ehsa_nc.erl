%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%% Nonce counter tracking for digest authentication.
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_nc).

-behaviour(gen_server).

%% API
-export([start_link/1]).

%% API
%% -export([create/0, insert/1, verify/2]).
-export([create/0, verify/2]).

%% gen_server callbacks
-export([code_change/3, handle_call/3, handle_cast/2, handle_info/2,
         init/1, terminate/2]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec start_link([{atom(), term()}]) -> {ok, pid()} | ignore | {error, term()}.
start_link(Args) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Create random nonce and insert it into nonce counter tracking
%% dictionary.
%% @end
%%--------------------------------------------------------------------
-spec create() -> binary().
create() ->
    Nonce = ehsa_binary:encode(crypto:rand_bytes(16)),
    ok = insert(Nonce),
    Nonce.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec insert(binary()) -> ok.
insert(Nonce) ->
    gen_server:call(?MODULE, {insert, Nonce}).

%% %%--------------------------------------------------------------------
%% %% @doc
%% %% @end
%% %%--------------------------------------------------------------------
%% -spec update(binary()) -> {ok, integer()} | undefined.
%% update(Nonce) ->
%%     gen_server:call(?MODULE, {update, Nonce}).

%%--------------------------------------------------------------------
%% @doc
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
%% handle_call({update, Nonce}, _From, _State = {NCs, Max, TTL}) ->
%%     {Reply, Next_NCs} =
%%         case dict:find(Nonce, NCs) of
%%             {ok, Value} when Value >= Max ->
%%                 {undefined, dict:erase(Nonce, NCs)};
%%             Found = {ok, _Value} ->
%%                 {Found, dict:update_counter(Nonce, 1, NCs)};
%%             error ->
%%                 {undefined, NCs}
%%         end,
%%     {reply, Reply, {Next_NCs, Max, TTL}};
handle_call({verify, Nonce, NC}, _From, _State = {NCs, Max, TTL}) ->
    {Reply, Next_NCs} =
        case dict:find(Nonce, NCs) of
            {ok, Value} when Value =:= NC ->
                {ok, dict:update_counter(Nonce, 1, NCs)};
            {ok, Value} when Value >= Max ->
                {undefined, dict:erase(Nonce, NCs)};
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
-spec init([{atom(), term()}]) -> {ok, term()} | {stop, term()}.
init(Args) ->
    NCs = dict:new(),
    Max = proplists:get_value(max_nc, Args, 16#ffffffff),
    TTL = proplists:get_value(nc_ttl, Args, 1800),
    {ok, {NCs, Max, 1000 * TTL}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.
