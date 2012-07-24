%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_basic).

-behaviour(gen_server).

%% API
-export([start_link/1]).

%% API
-export([verify_auth/2, verify_auth/3]).

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
    ehsa_common:start_link(?MODULE, Args).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary(),
                  ehsa:password_fun()) ->
                         {true, ehsa:credentials()} | {false, binary() | iolist()}.
verify_auth(Req_Header, Pwd_Fun) ->
    verify_auth(?MODULE, Req_Header, Pwd_Fun).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(atom() | pid(),
                  binary() | undefined,
                  ehsa:password_fun()) ->
                         {true, ehsa:credentials()} | {false, binary() | iolist()}.
verify_auth(Id, Req_Header, Pwd_Fun) ->
    Bin_Req_Header =
        case Req_Header of
            undefined ->
                <<>>;
            Other ->
                Other
        end,
    gen_server:call(Id, {verify_auth, Bin_Req_Header, Pwd_Fun}).

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
handle_call({verify_auth, Req_Header, Pwd_Fun}, _From, State) ->
    Reply =
        case binary:split(Req_Header, <<$ >>) of
            [Scheme, Req_Info] ->
                case ehsa_binary:to_lower(Scheme) of
                    <<"basic">> ->
                        verify_info(Req_Info, Pwd_Fun, State);
                    _Other ->
                        unauthorized(State)
                end;
            _Other ->
                unauthorized(State)
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
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec init([{atom(), term()}]) -> {ok, term()} | {stop, term()}.
init(Args) ->
    Realm = proplists:get_value(realm, Args, <<>>),
    Res_Header = [ <<"Basic ">>, ehsa_params:format(realm, Realm) ],
    {ok, Res_Header}.

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

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized(binary() | iolist()) ->
                          {false, binary() | iolist()}.
unauthorized(Res_Header) ->
    {false, Res_Header}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_info(binary(), ehsa:password_fun(), term()) ->
                         {true, ehsa:credentials()} | {false, binary() | iolist()}.
verify_info(Req_Info, Pwd_Fun, State) ->
    [Username, Password] = binary:split(base64:decode(Req_Info), <<$:>>),
    case Pwd_Fun(Username) of
        {ok, Password} ->
            {true, {Username, Password}};
        _Other ->
            unauthorized(State)
    end.
