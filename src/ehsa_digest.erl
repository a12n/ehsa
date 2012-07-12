%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%% MD4, MD5, SHA.
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_digest).

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
    <<"Digest">>.

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
verify_auth(_Method, _URI, _Req_Info, _All_Creds, Realm) ->
    %% TODO
    {false, <<>>, Realm}.

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
verify_auth(_Method, _URI, _Req_Info, _Req_Body, _All_Creds, Realm) ->
    %% TODO
    {false, <<>>, Realm}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec format_digest(binary()) -> binary().
format_digest(Digest) ->
    << <<(if N >= 10 -> N - 10 + $a; true -> N + $0 end)>> || <<N:4>> <= Digest >>.
