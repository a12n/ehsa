%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_basic).

-behaviour(ehsa_handler).

%% API
-export([auth_scheme/0, init_auth/1, verify_auth/5, verify_auth/6]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec auth_scheme() -> binary().
auth_scheme() ->
    <<"Basic">>.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec init_auth([{atom(), term()}]) -> term().
init_auth(Props) ->
    proplists:get_value(realm, Props, <<>>).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary(),
                  binary(),
                  binary(),
                  [ehsa:credentials()],
                  term()) ->
                         {true, binary() | iolist(), ehsa:credentials(), term()} |
                         {false, binary() | iolist(), term()}.
verify_auth(_Method, _URI, Req_Info, All_Creds, Realm) ->
    Authorized =
        case binary:split(base64:decode(Req_Info), [<<$:>>]) of
            [Usr, Pwd] ->
                Creds = {Usr, Pwd},
                case lists:member(Creds, All_Creds) of
                    true ->
                        Creds;
                    false ->
                        undefined
                end;
            _Other ->
                undefined
        end,
    case Authorized of
        {_Usr, _Pwd} ->
            {true, <<>>, Authorized, Realm};
        undefined ->
            {false, ehsa_params:format(realm, Realm), Realm}
    end.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary(),
                  binary(),
                  binary(),
                  ehsa:body(),
                  [ehsa:credentials()],
                  term()) ->
                         {true, fun((ehsa:body()) -> binary() | iolist()),
                          ehsa:credentials(), term()} |
                         {false, binary() | iolist(), term()}.
verify_auth(Method, URI, Req_Info, _Req_Body, All_Creds, Realm) ->
    case verify_auth(Method, URI, Req_Info, All_Creds, Realm) of
        {true, Res_Info, Authorized, _Realm} ->
            {true, fun(_Res_Body) -> Res_Info end, Authorized, Realm};
        Other ->
            Other
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

%% TODO

-endif.
