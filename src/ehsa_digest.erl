%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_digest).

-behaviour(ehsa_handler).

%% API
-export([auth_scheme/0, init/1, unauthorized_info/1, verify_auth/5]).

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
-spec init([{atom(), term()}]) -> term().
init(Args) ->
    NC = dict:new(),
    Realm = proplists:get_value(realm, Args, <<>>),
    {ok, {NC, Realm}}.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized_info(term()) ->
                               {false, binary() | iolist(), term()}.
unauthorized_info(State = {_NC, Realm}) ->
    {false, ehsa_params:format([ {realm, Realm},
                                 {qop, <<"auth, auth-int">>},
                                 {nonce, make_nonce()} ]), State}.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary(),
                  binary(),
                  ehsa:body(),
                  ehsa:password_fun(),
                  term()) ->
                         {true, binary() | iolist() | undefined,
                          ehsa:credentials(), term()} |
                         {false, binary() | iolist(), term()}.
verify_auth(Method, Req_Info, Req_Body, Pwd_Fun, State) ->
    %% TODO: Stale, check nonce count.
    Params = ehsa_params:parse(Req_Info),
    %% Check mandatory params
    {username, Username} = lists:keyfind(username, Params),
    {realm, Realm} = lists:keyfind(realm, Params),
    {nonce, Nonce} = lists:keyfind(nonce, Params),
    {uri, URI} = lists:keyfind(uri, Params),
    {response, Response} = lists:keyfind(response, Params),
    %% Implicitly check optional algorithm, qop, cnonce and nc params
    %% while figuring out how to compute response.
    <<"MD5">> = proplists:get_value(algorithm, Params, <<"MD5">>),
    QOP = proplists:get_value(qop, Params),
    HA2_Fun =
        case QOP of
            <<"auth-int">> ->
                fun() -> md5([Method, $:, URI, $:, md5(Req_Body)]) end;
            Other_1 when Other_1 =:= <<"auth">>;
                         Other_1 =:= undefined ->
                fun() -> md5([Method, $:, URI]) end
        end,
    Response_Fun =
        case QOP of
            undefined ->
                fun(HA1, HA2) -> md5([HA1, $:, Nonce, $:, HA2]) end;
            Other_2 when Other_2 =:= <<"auth">>;
                         Other_2 =:= <<"auth-int">> ->
                {cnonce, CNonce} = lists:keyfind(cnonce, Params),
                {nc, NC} = lists:keyfind(nc, Params),
                fun(HA1, HA2) -> md5([HA1, $:, Nonce, $:, NC, $:, CNonce, $:, QOP, $:, HA2]) end
        end,
    %% Check response
    case Pwd_Fun(Username) of
        {ok, Password} ->
            HA1 = md5([Username, $:, Realm, $:, Password]),
            HA2 = HA2_Fun(),
            Computed_Response = ehsa_binary:to_lower(Response_Fun(HA1, HA2)),
            case ehsa_binary:to_lower(Response) of
                Computed_Response ->
                    {true, undefined, {Username, Password}, State};
                _Other ->
                    unauthorized_info(State)
            end;
        _Other ->
            unauthorized_info(State)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec make_nonce() -> binary().
make_nonce() ->
    X = term_to_binary({node(), self(), make_ref(), now()}),
    ehsa_binary:format(crypto:md5(X)).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec md5(ehsa:body()) -> binary().
md5(Data) when is_function(Data, 0) ->
    md5(crypto:md5_init(), Data());
md5(Data) ->
    ehsa_binary:format(crypto:md5(Data)).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec md5(binary(), {iolist() | binary(), done | ehsa:body_fun()}) -> binary().
md5(Ctx, {Data, done}) ->
    ehsa_binary:format(crypto:md5_final(crypto:md5_update(Ctx, Data)));
md5(Ctx, {Data, Next}) ->
    md5(crypto:md5_update(Ctx, Data), Next()).
