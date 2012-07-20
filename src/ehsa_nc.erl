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
-export([start/1, start_link/1, stop/0]).

%% API
-export([insert/1, update/1]).

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
-spec start([{atom(), term()}]) -> {ok, pid()} | ignore | {error, term()}.
start(Args) ->
    gen_server:start({local, ?MODULE}, ?MODULE, Args, []).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec start_link([{atom(), term()}]) -> {ok, pid()} | ignore | {error, term()}.
start_link(Args) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec stop() -> ok.
stop() ->
    gen_server:cast(?MODULE, stop).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec insert(binary()) -> ok.
insert(Nonce) ->
    gen_server:call(?MODULE, {insert, Nonce}).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec update(binary()) -> {ok, integer()} | undefined.
update(Nonce) ->
    gen_server:call(?MODULE, {update, Nonce}).

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
handle_call({insert, Nonce}, _From, _State = {Dict, Max, TTL}) ->
    error = dict:find(Nonce, Dict),
    Next_Dict = dict:update_counter(Nonce, 1, Dict),
    erlang:send_after(TTL, self(), {delete, Nonce}),
    {reply, ok, {Next_Dict, Max, TTL}};
handle_call({update, Nonce}, _From, _State = {Dict, Max, TTL}) ->
    {Reply, Next_Dict} =
        case dict:find(Nonce, Dict) of
            {ok, Value} when Value >= Max ->
                {undefined, dict:erase(Nonce, Dict)};
            Found = {ok, _Value} ->
                {Found, dict:update_counter(Nonce, 1, Dict)};
            error ->
                {undefined, Dict}
        end,
    {reply, Reply, {Next_Dict, Max, TTL}};
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
handle_info({delete, Nonce}, _State = {Dict, TTL}) ->
    Next_Dict = dict:erase(Nonce, Dict),
    {noreply, {Next_Dict, TTL}};
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec init([{atom(), term()}]) -> {ok, term()} | {stop, term()}.
init(Args) ->
    NC_Max = proplists:get_value(nc_max, Args, 16#ffffffff),
    Nonce_TTL = proplists:get_value(nonce_ttl, Args, 1800),
    {ok, {dict:new(), NC_Max, 1000 * Nonce_TTL}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.
