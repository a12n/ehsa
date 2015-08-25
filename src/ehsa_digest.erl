%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@bestmx.ru>
%%% @doc
%%% Digest authentication handling.
%%% @end
%%% For copyright notice see LICENSE.
%%%-------------------------------------------------------------------
-module(ehsa_digest).

%% API
-export([ha1/3, verify_auth/3, verify_auth/4, verify_auth_int/4,
         verify_auth_int/5]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Computes `md5([Username, $:, Realm, $:, Password])'. Result is
%% hex-encoded lower case binary string.
%% @end
%%--------------------------------------------------------------------
-spec ha1(binary(),
          binary(),
          binary()) -> binary().

ha1(Username, Realm, Password) ->
    md5([Username, $:, Realm, $:, Password]).

%%--------------------------------------------------------------------
%% @equiv verify_auth(Method, ReqHeader, PwdFun, _Options = [])
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(atom() | binary(),
                  iodata() | undefined,
                  ehsa:password_fun()) ->
                         {true, any()} | {false, iodata()}.

verify_auth(Method, ReqHeader, PwdFun) ->
    verify_auth(Method, ReqHeader, PwdFun, []).

%%--------------------------------------------------------------------
%% @equiv verify_auth_int(Method, ReqHeader, _ReqBody = undefined, PwdFun, Options)
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(atom() | binary(),
                  iodata() | undefined,
                  ehsa:password_fun(),
                  ehsa:options()) ->
                         {true, any()} | {false, iodata()}.

verify_auth(Method, ReqHeader, PwdFun, Options) ->
    verify_auth_int(Method, ReqHeader, undefined, PwdFun, Options).

%%--------------------------------------------------------------------
%% @equiv verify_auth_int(Method, ReqHeader, ReqBody, PwdFun, _Options = [])
%% @end
%%--------------------------------------------------------------------
-spec verify_auth_int(atom() | binary(),
                      iodata() | undefined,
                      iodata() | undefined,
                      ehsa:password_fun()) ->
                             {true, any()} | {false, iodata()}.

verify_auth_int(Method, ReqHeader, ReqBody, PwdFun) ->
    verify_auth_int(Method, ReqHeader, ReqBody, PwdFun, []).

%%--------------------------------------------------------------------
%% @doc
%% Verify digest authentication of HTTP request.
%%
%% Request's `Method' could be either atom (e.g. <code>'GET'</code>)
%% or binary (e.g. `<<"POST">>').
%%
%% `ReqHeader' is value of "Authorization" header from client (it may
%% be `undefined').
%%
%% Request's body `ReqBody' is used to check content's integrity. If
%% it's `undefined' integrity will not be checked, and server
%% responses will not signal a support for it.
%%
%% `PwdFun' is a function which, for a given user name, must return
%% `undefined' if there is no such user, or `{Password, Opaque}'. The
%% `Password' is either cleartext password as binary string, or
%% `{digest, Digest}', where `Digest' is computed as
%% `ehsa_digest:ha1(Username, Realm, ClearPassword)'. It's hex-encoded
%% lower case binary string.
%%
%% Usually `PwdFun' performs some useful work (e.g., does a database
%% query). It should return the result in `Opaque' term, which will be
%% passed to the caller untouched.
%%
%% The available `Options' are:
%% <dl>
%% <dt>`{realm, Realm :: binary()}'</dt>
%% <dd>Binary string `Realm' will be used for realm in "401
%% Unauthorized" responses. If unspecified, it's considered to be empty
%% string.</dd>
%% <dt>`{domain, Domain :: [binary()]}'</dt>
%% <dd>List of URIs that define protection space (see
%% [http://tools.ietf.org/html/rfc2617#section-3.2.1]). It's empty
%% list by default.</dd>
%% </dl>
%%
%% Function returns either `{true, Opaque :: any()}' if authentication
%% information is valid (`Opaque' is from the `PwdFun'), or `{false,
%% ResHeader :: iodata()}'. Returned `ResHeader' must be used as a
%% value for "WWW-Authenticate" header of the response.
%% @end
%%--------------------------------------------------------------------
-spec verify_auth_int(atom() | binary(),
                      iodata() | undefined,
                      iodata() | undefined,
                      ehsa:password_fun(),
                      ehsa:options()) ->
                             {true, any()} | {false, iodata()}.

verify_auth_int(Method, undefined, ReqBody, PwdFun, Options) ->
    verify_auth_int(Method, <<>>, ReqBody, PwdFun, Options);

verify_auth_int(Method, ReqHeader, ReqBody, PwdFun, Options) when is_list(ReqHeader) ->
    verify_auth_int(Method, iolist_to_binary(ReqHeader), ReqBody, PwdFun, Options);

verify_auth_int(Method, ReqHeader, ReqBody, PwdFun, Options) when is_atom(Method) ->
    verify_auth_int(atom_to_binary(Method, latin1), ReqHeader, ReqBody, PwdFun, Options);

verify_auth_int(Method, ReqHeader, ReqBody, PwdFun, Options) ->
    Int = (ReqBody =/= undefined),
    case binary:split(ReqHeader, <<$ >>) of
        [Scheme, ReqInfo] ->
            case ehsa_binary:to_lower(Scheme) of
                <<"digest">> ->
                    verify_info(Method, ReqInfo, ReqBody, PwdFun, Options);
                _Other ->
                    %% Invalid auth scheme
                    unauthorized(false, Int, Options)
            end;
        _Other ->
            %% Invalid/missing auth information
            unauthorized(false, Int, Options)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec ha2(binary() | undefined,
          binary(),
          binary(),
          iodata() | undefined) -> binary().

ha2(_QOP = <<"auth-int">>, Method, URI, ReqBody)
  when ReqBody =/= undefined ->
    md5([Method, $:, URI, $:, md5(ReqBody)]);

ha2(QOP, Method, URI, _ReqBody)
  when QOP =:= <<"auth">>;
       QOP =:= undefined ->
    md5([Method, $:, URI]).

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec md5(iodata()) -> binary().

md5(Data) ->
    ehsa_binary:encode(crypto:hash(md5, Data)).

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
                   boolean(),
                   ehsa:options()) -> {false, iodata()}.

unauthorized(Stale, Int, Options) ->
    Domain = proplists:get_value(domain, Options, []),
    Nonce = ehsa_nc:create(),
    Realm = proplists:get_value(realm, Options, <<>>),
    ResHeader =
        [ <<"Digest ">>,
          ehsa_params:format(realm, Realm),
          <<", ">>,
          ehsa_params:format(qop, case Int of
                                      true ->
                                          <<"auth,auth-int">>;
                                      false ->
                                          <<"auth">>
                                  end),
          <<", ">>,
          ehsa_params:format(nonce, Nonce),
          case Domain of
              [_H | _T] ->
                  [ <<", ">>,
                    ehsa_params:format(domain, ehsa_binary:join(Domain, <<" ">>)) ];
              _Other ->
                  []
          end,
          case Stale of
              true ->
                  [ <<", ">>,
                    ehsa_params:format(stale, <<"true">>) ];
              false ->
                  []
          end ],
    {false, ResHeader}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_info(binary(),
                  binary(),
                  iodata() | undefined,
                  ehsa:password_fun(),
                  ehsa:options()) ->
                         {true, any()} | {false, iodata()}.

verify_info(Method, ReqInfo, ReqBody, PwdFun, Options) ->
    Int = (ReqBody =/= undefined),
    Params = ehsa_params:parse(ReqInfo),
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
    case Algorithm of
        <<"MD5">> ->
            ok
    end,
    case {QOP, (CNonce =/= undefined) and (NC =/= undefined)} of
        {undefined, _} ->
            ok;
        {<<"auth">>, true} ->
            ok;
        {<<"auth-int">>, true} when Int ->
            ok
    end,
    %% Check NC
    case verify_nc(QOP, Nonce, NC) of
        ok ->
            %% Check response
            case PwdFun(Username) of
                undefined ->
                    %% Invalid credentials
                    unauthorized(false, Int, Options);
                {Password, Opaque} ->
                    HA1 =
                        case Password of
                            {digest, Digest} ->
                                Digest;
                            _Clear ->
                                ha1(Username, Realm, Password)
                        end,
                    ComputedResponse =
                        response(QOP,
                                 HA1,
                                 Nonce,
                                 NC,
                                 CNonce,
                                 ha2(QOP, Method, URI, ReqBody)),
                    case ehsa_binary:to_lower(Response) of
                        ComputedResponse ->
                            {true, Opaque};
                        _Other ->
                            %% Invalid response
                            unauthorized(false, Int, Options)
                    end
            end;
        badarg ->
            %% Invalid NC
            unauthorized(false, Int, Options);
        undefined ->
            %% Stale nonce
            unauthorized(true, Int, Options)
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
    ehsa_nc:verify(Nonce, binary_to_integer(NC, 16)).

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

ehsa_digest_test_() ->
    {setup,
     fun() -> {ok, Pid} = ehsa_nc:start_link([]), Pid end,
     fun(Pid) -> gen_server:cast(Pid, stop) end,
     fun(_Pid) ->
             Realm = <<"testrealm@host.com">>,
             Options = [{realm, Realm}],
             Password = fun(<<"Mufasa">>) -> {<<"Circle Of Life">>, 1};
                           (<<"Qobb">>) -> {<<"Mellon">>, 2};
                           (_Other) -> undefined end,
             [ ?_assertMatch(
                  {true, 1},
                  verify_auth(<<"GET">>,
                              <<"Digest username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", response=\"670fd8c2df070c60b045671b8b24ff02\"">>,
                              Password,
                              Options)
                 ),
               ?_assertMatch(
                  {false, _ResHeader},
                  verify_auth(<<"GET">>,
                              <<"Digest username=\"Mafaza\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000002, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>,
                              Password)
                 ),
               ?_assertMatch(
                  {true, 1},
                  verify_auth('GET',
                              ["Digest ", "username=\"Mufasa\"", [", realm=\"testrealm@host.com\""], ", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"", ",uri=\"/dir/index.html\", response=\"670fd8c2df070c60b045671b8b24ff02\""],
                              Password,
                              Options)
                 ) ]
     end}.

-endif.
