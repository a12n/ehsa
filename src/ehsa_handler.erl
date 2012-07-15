%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_handler).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-callback auth_scheme() ->
    Scheme :: binary().

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-callback init(Args :: [{atom(), term()}]) ->
    {ok, State :: term()} | {stop, Reason :: term()}.

%%--------------------------------------------------------------------
%% @doc
%% Constructs "Unathorized" response auth parameters. Returns `false'
%% for consistency with verify_auth function.
%% @end
%%--------------------------------------------------------------------
-callback unauthorized_info(State :: term()) ->
    {false, Res_Info :: binary() | iolist(), Next_State :: term()}.

%%--------------------------------------------------------------------
%% @doc
%% Check authentication parameters and body integrity.
%% @end
%%--------------------------------------------------------------------
-callback verify_auth(Method :: binary(),
                      Req_Info :: binary(),
                      Req_Body :: ehsa:body(),
                      Credentials :: ehsa:credentials_fun(),
                      State :: term()) ->
    {true, Res_Info :: binary() | iolist() | undefined,
     Authorized :: ehsa:credentials(), Next_State :: term()} |
    {false, Res_Info :: binary() | iolist(), Next_State :: term()}.
