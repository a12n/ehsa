%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%% @todo Stale nonce, check nonce count, authentication-info.
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
    Domain = proplists:get_value(domain, Args, []),
    QOP = <<"auth, auth-int">>,
    Realm = proplists:get_value(realm, Args, <<>>),
    Res_Info = ehsa_params:format([ {realm, Realm},
                                    {qop, QOP},
                                    {domain, ehsa_binary:join(Domain, <<" ">>)} ]),
    {ok, Res_Info}.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized_info(term()) ->
                               {false, binary() | iolist(), term()}.
unauthorized_info(State = Res_Info) ->
    Nonce = make_nonce(),
    %% ehsa_nc:insert(Nonce),
    {false, [ Res_Info,
              <<", ">>,
              ehsa_params:format(nonce, Nonce) ], State}.

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
    Params = ehsa_params:parse(Req_Info),
    %% Check mandatory params
    {username, Username} = lists:keyfind(username, 1, Params),
    {realm, Realm} = lists:keyfind(realm, 1, Params),
    {nonce, Nonce} = lists:keyfind(nonce, 1, Params),
    {uri, URI} = lists:keyfind(uri, 1, Params),
    {response, Response} = lists:keyfind(response, 1, Params),
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
                {cnonce, CNonce} = lists:keyfind(cnonce, 1, Params),
                {nc, NC} = lists:keyfind(nc, 1, Params),
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
                    %% TODO: Check stale nonce.
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
    ehsa_binary:encode(crypto:rand_bytes(16)).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec md5(ehsa:body()) -> binary().
md5(Data) when is_function(Data, 0) ->
    md5(crypto:md5_init(), Data());
md5(Data) ->
    ehsa_binary:encode(crypto:md5(Data)).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec md5(binary(), {iolist() | binary(), done | ehsa:body_fun()}) -> binary().
md5(Ctx, {Data, done}) ->
    ehsa_binary:encode(crypto:md5_final(crypto:md5_update(Ctx, Data)));
md5(Ctx, {Data, Next}) ->
    md5(crypto:md5_update(Ctx, Data), Next()).

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

auth_scheme_0_test_() ->
    ?_test( <<"digest">> = ehsa_binary:to_lower(auth_scheme()) ).

init_1_test_() ->
    [ ?_test( {ok, _} = init([]) ),
      ?_test( {ok, _} = init([{realm, <<"Hoom">>}]) ) ].

unauthorized_info_1_test_() ->
    %% TODO
    [].

verify_auth_5_test_() ->
    Pwd_Fun = fun(<<"Mufasa">>) -> {ok, <<"Circle Of Life">>};
                 (<<"Qobb">>) -> {ok, <<"Mellon">>};
                 (_Other) -> undefined
              end,
    Realm = <<"testrealm@host.com">>,
    Body = <<>>,
    {ok, State} = init([{realm, Realm}]),
    [ fun() ->
              {true, _Res_Info, {<<"Mufasa">>, <<"Circle Of Life">>}, _} =
                  verify_auth(<<"GET">>,
                              <<"username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", response=\"670fd8c2df070c60b045671b8b24ff02\"">>,
                              Body,
                              Pwd_Fun,
                              State)
      end,
      fun() ->
              {true, _Res_Info, {<<"Mufasa">>, <<"Circle Of Life">>}, _} =
                  verify_auth(<<"GET">>,
                              <<"username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>,
                              Body,
                              Pwd_Fun,
                              State)
      end,
      fun() ->
              {false, _Res_Info, _} =
                  verify_auth(<<"GET">>,
                              <<"username=\"Mafaza\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000002, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>,
                              Body,
                              Pwd_Fun,
                              State)
      end ].

-endif.
