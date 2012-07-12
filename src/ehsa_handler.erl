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
-callback init_auth(Props :: [{atom(), term()}]) ->
    State :: term().

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-callback verify_auth(Method :: binary(),
                      URI :: binary(),
                      Req_Info :: binary(),
                      Credentials :: [ehsa:credentials()],
                      State :: term()) ->
    {true, Res_Info :: binary() | iolist(), Authorized :: ehsa:credentials(),
     Next_State :: term()} |
    {false, Res_Info :: binary() | iolist(), Next_State :: term()}.

%%--------------------------------------------------------------------
%% @doc
%% Body integrity protection.
%% @end
%%--------------------------------------------------------------------
-callback verify_auth(Method :: binary(),
                      URI :: binary(),
                      Req_Info :: binary(),
                      Req_Body :: ehsa:body(),
                      Credentials :: [ehsa:credentials()],
                      State :: term()) ->
    {true, fun((Res_Body :: ehsa:body()) -> Res_Info :: binary() | iolist()),
              Authorized :: ehsa:credentials(), Next_State :: term()} |
    {false, Res_Info :: binary() | iolist(), Next_State :: term()}.
