%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa).

-behaviour(gen_server).

%% Types
-export_type([body/0, body_fun/0, credentials/0, password_fun/0]).

%% API
-export([start/1, start_link/1, stop/0, stop/1]).

%% API
-export([unauthorized_info/0, unauthorized_info/1, verify_auth/4,
         verify_auth/5]).

%% gen_server callbacks
-export([code_change/3, handle_call/3, handle_cast/2, handle_info/2,
         init/1, terminate/2]).

%%%===================================================================
%%% Types
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-type body() :: binary() | iolist() | body_fun().

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-type body_fun() :: fun(() -> {binary() | iolist(), done | body_fun()}).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-type credentials() :: {binary(), binary()}.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-type password_fun() :: fun((binary()) -> {ok, binary()} | undefined).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec start([{atom(), term()}]) -> {ok, pid()} | ignore | {error, term()}.
start(Args) ->
    do_start(start, Args).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec start_link([{atom(), term()}]) -> {ok, pid()} | ignore | {error, term()}.
start_link(Args) ->
    do_start(start_link, Args).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec stop() -> ok.
stop() ->
    stop(?MODULE).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec stop(atom() | pid()) -> ok.
stop(Id) ->
    gen_server:cast(Id, stop).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized_info() -> binary() | iolist().
unauthorized_info() ->
    unauthorized_info(?MODULE).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized_info(atom() | pid()) -> binary() | iolist().
unauthorized_info(Id) ->
    gen_server:call(Id, unauthorized_info).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary(),
                  binary(),
                  ehsa:body(),
                  ehsa:password_fun()) ->
                         {true, binary() | iolist() | undefined,
                          ehsa:credentials()} |
                         {false, binary() | iolist()}.
verify_auth(Method, Req_Info, Req_Body, Pwd_Fun) ->
    verify_auth(?MODULE, Method, Req_Info, Req_Body, Pwd_Fun).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(atom() | pid(),
                  binary(),
                  binary(),
                  ehsa:body(),
                  ehsa:password_fun()) ->
                         {true, binary() | iolist() | undefined,
                          ehsa:credentials()} |
                         {false, binary() | iolist()}.
verify_auth(Id, Method, Req_Info, Req_Body, Pwd_Fun) ->
    gen_server:call(Id, {verify_auth, Method, Req_Info, Req_Body, Pwd_Fun}).

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
handle_call(unauthorized_info, _From, {Handler, State}) ->
    {false, Res_Info, Next_State} = Handler:unauthorized_info(State),
    Scheme = Handler:auth_scheme(),
    {reply, [Scheme, <<" ">>, Res_Info], {Handler, Next_State}};
handle_call({verify_auth, Method, Req_Header, Req_Body, Pwd_Fun}, _From, {Handler, State}) ->
    [Req_Scheme, Req_Info] = binary:split(Req_Header, <<" ">>),
    Scheme = Handler:auth_scheme(),
    Handler_Reply =
        case ehsa_binary:to_lower(Req_Scheme) =:= ehsa_binary:to_lower(Scheme) of
            true ->
                Handler:verify_auth(Method, Req_Info, Req_Body, Pwd_Fun, State);
            false ->
                Handler:unauthorized_info(State)
        end,
    case Handler_Reply of
        {true, undefined, Authorized, Next_State} ->
            {reply, {true, undefined, Authorized}, {Handler, Next_State}};
        {true, Res_Info, Authorized, Next_State} ->
            {reply, {true, [Scheme, <<" ">>, Res_Info], Authorized}, {Handler, Next_State}};
        {false, Res_Info, Next_State} ->
            {reply, {false, [Scheme, <<" ">>, Res_Info]}, {Handler, Next_State}}
    end;
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
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec init([{atom(), term()}]) -> {ok, term()} | {stop, term()}.
init(Args) ->
    case proplists:get_value(handler, Args) of
        undefined ->
            {stop, no_handler};
        Handler ->
            case Handler:init(Args) of
                {ok, State} ->
                    {ok, {Handler, State}};
                {stop, Reason} ->
                    {stop, Reason}
            end
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec do_start(start | start_link, [{atom(), term()}]) ->
                      {ok, pid()} | ignore | {error, term()}.
do_start(Fun_Name, Args) ->
    case proplists:get_value(register, Args, true) of
        true ->
            gen_server:Fun_Name({local, ?MODULE}, ?MODULE, Args, []);
        false ->
            gen_server:Fun_Name(?MODULE, Args, [])
    end.
