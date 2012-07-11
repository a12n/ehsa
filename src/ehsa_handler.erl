%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_handler).

-callback init_auth(Props :: [{atom(), term()}]) ->
    State :: term().

-callback supports_auth_scheme(Scheme :: binary()) ->
    boolean().

-callback verify_auth(Method :: binary(),
                      URI :: binary(),
                      Req_Header :: binary(),
                      Credentials :: [{binary(), binary()}],
                      State :: term()) ->
    {true, Res_Header :: binary(), Authorized :: {binary(), binary()},
     Next_State :: term()} |
    {false, Res_Header :: binary(), Next_State :: term()}.

-callback verify_auth(Method :: binary(),
                      URI :: binary(),
                      Req_Header :: binary(),
                      Req_Body :: binary() | iolist(),
                      Credentials :: [{binary(), binary()}],
                      State :: term()) ->
    {true, fun(Res_Body :: binary() -> Res_Header :: binary()),
              Authorized :: {binary(), binary()}, Next_State :: term()} |
    {false, Res_Header :: binary(), Next_State :: term()}.
