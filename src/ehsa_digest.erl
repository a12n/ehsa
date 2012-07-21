%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_digest).

-behaviour(gen_server).

%% API
-export([start_link/1]).

%% API
-export([verify_auth/4, verify_auth/5]).

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
start_link(Args) ->
    ehsa_common:start_link(?MODULE, Args).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(atom() | binary(),
                  binary(),
                  binary() | iolist(),
                  ehsa:password_fun()) ->
                         {true, ehsa:credentials()} | {false, binary() | iolist()}.
verify_auth(Method, Req_Header, Req_Body, Pwd_Fun) ->
    verify_auth(?MODULE, Method, Req_Header, Req_Body, Pwd_Fun).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(atom() | pid(),
                  atom() | binary(),
                  binary() | undefined,
                  binary() | iolist(),
                  ehsa:password_fun()) ->
                         {true, ehsa:credentials()} | {false, binary() | iolist()}.
verify_auth(Id, Method, Req_Header, Req_Body, Pwd_Fun) ->
    Bin_Method =
        case is_atom(Method) of
            true ->
                atom_to_binary(Method, latin1);
            false ->
                Method
        end,
    Bin_Req_Header =
        case Req_Header of
            undefined ->
                <<>>;
            Other ->
                Other
        end,
    gen_server:call(Id, {verify_auth, Bin_Method, Bin_Req_Header, Req_Body, Pwd_Fun}).

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
handle_call({verify_auth, Method, Req_Header, Req_Body, Pwd_Fun}, _From, State) ->
    Reply =
        case binary:split(Req_Header, <<$ >>) of
            [Scheme, Req_Info] ->
                case ehsa_binary:to_lower(Scheme) of
                    <<"digest">> ->
                        verify_info(Method, Req_Info, Req_Body, Pwd_Fun, State);
                    _Other ->
                        unauthorized(false, <<"Invalid auth scheme">>, State)
                end;
            _Other ->
                unauthorized(false, <<"Invalid/missing auth information">>, State)
        end,
    {reply, Reply, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
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
-spec init([{atom(), term()}]) -> {ok, binary() | iolist()}.
init(Args) ->
    Domain = proplists:get_value(domain, Args, []),
    Realm = proplists:get_value(realm, Args, <<>>),
    Res_Header = [ <<"Digest ">>,
                   ehsa_params:format(realm, Realm),
                   <<", ">>,
                   ehsa_params:format(qop, <<"auth,auth-int">>),
                   case Domain of
                       [_H | _T] ->
                           [ <<", ">>,
                             ehsa_params:format(domain, ehsa_binary:join(Domain, <<" ">>)) ];
                       _Other ->
                           []
                   end ],
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
-spec ha1(binary(),
          binary(),
          binary()) -> binary().
ha1(Username, Realm, Password) ->
    md5([Username, $:, Realm, $:, Password]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec ha2(binary() | undefined,
          binary(),
          binary(),
          binary() | iolist()) -> binary().
ha2(_QOP = <<"auth-int">>, Method, URI, Req_Body) ->
    md5([Method, $:, URI, $:, md5(Req_Body)]);
ha2(QOP, Method, URI, _Req_Body)
  when QOP =:= <<"auth">>;
       QOP =:= undefined ->
    md5([Method, $:, URI]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec md5(binary() | iolist()) -> binary().
md5(Data) ->
    ehsa_binary:encode(crypto:md5(Data)).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec response(binary() | undefined,
               binary(),
               binary(),
               binary() | undefined,
               binary() | undefined,
               binary()) -> binary().
response(_QOP = undefined, HA1, Nonce, _NC, _CNonce, HA2) ->
    md5([HA1, $:, Nonce, $:, HA2]);
response(QOP, HA1, Nonce, NC, CNonce, HA2)
  when QOP =:= <<"auth">>;
       QOP =:= <<"auth-int">> ->
    md5([HA1, $:, Nonce, $:, NC, $:, CNonce, $:, QOP, $:, HA2]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized(boolean(),
                   binary() | iolist(),
                   binary() | iolist()) ->
                          {false, binary() | iolist()}.
unauthorized(Stale, _Comment, Res_Header) ->
    Nonce = ehsa_nc:create(),
    {false, [ Res_Header,
              %% <<", ">>,
              %% ehsa_params:format(comment, Comment),
              <<", ">>,
              ehsa_params:format(nonce, Nonce),
              case Stale of
                  true ->
                      [ <<", ">>,
                        ehsa_params:format(stale, <<"true">>) ];
                  false ->
                      []
              end ]}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_info(binary(),
                  binary(),
                  binary() | iolist(),
                  ehsa:password_fun(),
                  binary() | iolist()) ->
                         {true, ehsa:credentials()} | {false, binary() | iolist()}.
verify_info(Method, Req_Info, Req_Body, Pwd_Fun, State) ->
    Params = ehsa_params:parse(Req_Info),
    %% Mandatory params
    {username, Username} = lists:keyfind(username, 1, Params),
    {realm, Realm} = lists:keyfind(realm, 1, Params),
    {nonce, Nonce} = lists:keyfind(nonce, 1, Params),
    {uri, URI} = lists:keyfind(uri, 1, Params),
    {response, Response} = lists:keyfind(response, 1, Params),
    %% Optional params
    Algorithm = proplists:get_value(algorithm, Params, <<"MD5">>),
    CNonce = proplists:get_value(cnonce, Params),
    NC = proplists:get_value(nc, Params),
    QOP = proplists:get_value(qop, Params),
    %% Check optional params
    true = (Algorithm =:= <<"MD5">>),
    true = ((QOP =:= undefined) or (((QOP =:= <<"auth">>) or
                                    (QOP =:= <<"auth-int">>)) and
                                   (CNonce =/= undefined) and (NC =/= undefined))),
    %% Check NC
    case verify_nc(QOP, Nonce, NC) of
        ok ->
            %% Check response
            case Pwd_Fun(Username) of
                {ok, Password} ->
                    Computed_Response =
                        response(QOP,
                                 ha1(Username, Realm, Password),
                                 Nonce,
                                 NC,
                                 CNonce,
                                 ha2(QOP, Method, URI, Req_Body)),
                    case ehsa_binary:to_lower(Response) of
                        Computed_Response ->
                            {true, {Username, Password}};
                        _Other ->
                            unauthorized(false, <<"Invalid response">>, State)
                    end;
                _Other ->
                    unauthorized(false, <<"Invalid credentials">>, State)
            end;
        badarg ->
            unauthorized(false, <<"Invalid NC">>, State);
        undefined ->
            unauthorized(true, <<"Stale nonce">>, State)
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_nc(binary() | undefined,
                binary(),
                binary() | undefined) -> ok | badarg | undefined.
verify_nc(_QOP = undefined, _Nonce, _NC) ->
    ok;
verify_nc(_QOP, Nonce, NC) ->
    ehsa_nc:verify(Nonce, ehsa_binary:to_integer(NC, 16)).

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

%% auth_scheme_0_test_() ->
%%     ?_test( <<"digest">> = ehsa_binary:to_lower(auth_scheme()) ).
%%
%% init_1_test_() ->
%%     [ ?_test( {ok, _} = init([]) ),
%%       ?_test( {ok, _} = init([{realm, <<"Hoom">>}]) ) ].
%%
%% unauthorized_info_1_test_() ->
%%     %% TODO
%%     [].
%%
%% verify_auth_5_test_() ->
%%     Pwd_Fun = fun(<<"Mufasa">>) -> {ok, <<"Circle Of Life">>};
%%                  (<<"Qobb">>) -> {ok, <<"Mellon">>};
%%                  (_Other) -> undefined
%%               end,
%%     Realm = <<"testrealm@host.com">>,
%%     Body = <<>>,
%%     {ok, State} = init([{realm, Realm}]),
%%     [ fun() ->
%%               {true, _Res_Info, {<<"Mufasa">>, <<"Circle Of Life">>}, _} =
%%                   verify_auth(<<"GET">>,
%%                               <<"username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", response=\"670fd8c2df070c60b045671b8b24ff02\"">>,
%%                               Body,
%%                               Pwd_Fun,
%%                               State)
%%       end,
%%       fun() ->
%%               {true, _Res_Info, {<<"Mufasa">>, <<"Circle Of Life">>}, _} =
%%                   verify_auth(<<"GET">>,
%%                               <<"username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>,
%%                               Body,
%%                               Pwd_Fun,
%%                               State)
%%       end,
%%       fun() ->
%%               {false, _Res_Info, _} =
%%                   verify_auth(<<"GET">>,
%%                               <<"username=\"Mafaza\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000002, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>,
%%                               Body,
%%                               Pwd_Fun,
%%                               State)
%%       end ].

-endif.
