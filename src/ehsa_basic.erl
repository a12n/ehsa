%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@bestmx.ru>
%%% @doc
%%% Basic authentication handling.
%%% @end
%%% For copyright notice see LICENSE.
%%%-------------------------------------------------------------------
-module(ehsa_basic).

%% API
-export([verify_auth/2, verify_auth/3]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @equiv verify_auth(ReqHeader, PwdFun, _Options = [])
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(iodata() | undefined,
                  ehsa:password_fun() | ehsa:check_password_fun()) ->
                         {true, any()} | {false, iodata()}.

verify_auth(ReqHeader, PwdFun) ->
    verify_auth(ReqHeader, PwdFun, []).

%%--------------------------------------------------------------------
%% @doc
%% Verify basic authentication of HTTP request.
%%
%% `ReqHeader' is value of "Authorization" header from client (it may
%% be `undefined').
%%
%% `PwdFun' is either a `ehsa:password_fun()' or
%% `ehsa:check_password_fun()'.
%%
%% `ehsa:password_fun()' is a function which, for a given user name,
%% must return `undefined' if there is no such user, or `{Password,
%% Opaque}'. The `Password' is either cleartext password as binary
%% string, or `{digest, Digest}', where `Digest' is computed as
%% `ehsa_digest:ha1(Username, Realm, ClearPassword)'. It's hex-encoded
%% lower case binary string.
%%
%% `ehsa:check_password_fun()' is a function which performs password
%% validation by itself, and must return either `{true, Opaque}' if
%% the password is valid, or `false'.
%%
%% Usually `PwdFun' performs some useful work (e.g., does a database
%% query). It should return the result in `Opaque' term, which will be
%% passed to the caller untouched.
%%
%% `Options' is a list of properties. The available options are:
%% <dl>
%% <dt>`{realm, Realm :: binary()}'</dt>
%% <dd>Binary string `Realm' will be used for realm in "401
%% Unauthorized" responses. If unspecified, it's considered to be empty
%% string.</dd>
%% </dl>
%%
%% Function returns either `{true, Opaque :: any()}' if authentication
%% information is valid (`Opaque' is from the `PwdFun'), or `{false,
%% ResHeader :: iodata()}'. Returned `ResHeader' must be used as a
%% value for "WWW-Authenticate" header of the response.
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(iodata() | undefined,
                  ehsa:password_fun() | ehsa:check_password_fun(),
                  ehsa:options()) ->
                         {true, any()} | {false, iodata()}.

verify_auth(undefined, PwdFun, Options) ->
    verify_auth(<<>>, PwdFun, Options);

verify_auth(ReqHeader, PwdFun, Options) when is_list(ReqHeader) ->
    verify_auth(iolist_to_binary(ReqHeader), PwdFun, Options);

verify_auth(ReqHeader, PwdFun, Options) ->
    case binary:split(ReqHeader, <<$ >>) of
        [Scheme, ReqInfo] ->
            case ehsa_binary:to_lower(Scheme) of
                <<"basic">> ->
                    verify_info(ReqInfo, PwdFun, Options);
                _Other ->
                    unauthorized(Options)
            end;
        _Other ->
            unauthorized(Options)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized(ehsa:options()) -> {false, iodata()}.

unauthorized(Options) ->
    Realm = proplists:get_value(realm, Options, <<>>),
    ResHeader = [ <<"Basic ">>, ehsa_params:format(realm, Realm) ],
    {false, ResHeader}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_credentials(binary(), binary(),
                         ehsa:password_fun() | ehsa:check_password_fun(),
                         ehsa:options()) ->
                                {true, any()} | {false, iodata()}.

%% PwdFun returns password for a username
verify_credentials(Username, Password, PwdFun, Options)
  when is_function(PwdFun, 1) ->
    case PwdFun(Username) of
        {{digest, Digest}, Opaque} ->
            Realm = proplists:get_value(realm, Options, <<>>),
            case ehsa_digest:ha1(Username, Realm, Password) of
                Digest ->
                    {true, Opaque};
                _Other ->
                    unauthorized(Options)
            end;
        {Password, Opaque} ->
            {true, Opaque};
        _Other ->
            unauthorized(Options)
    end;

%% PwdFun checks password's valid for a username
verify_credentials(Username, Password, PwdFun, Options)
  when is_function(PwdFun, 2) ->
    case PwdFun(Username, Password) of
        {true, Opaque} ->
            {true, Opaque};
        false ->
            unauthorized(Options)
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_info(binary(),
                  ehsa:password_fun() | ehsa:check_password_fun(),
                  ehsa:options()) ->
                         {true, any()} | {false, iodata()}.

verify_info(ReqInfo, PwdFun, Options) ->
    [Username, Password] = binary:split(base64:decode(ReqInfo), <<$:>>),
    verify_credentials(Username, Password, PwdFun, Options).

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

password(<<"admin">>) -> {{digest, ehsa_digest:ha1(<<"admin">>, <<"DaRk">>, <<"123">>)}, 1};
password(<<"guest">>) -> {<<>>, 2};
password(<<"xyzzy">>) -> {<<"1,.:235asd\/">>, 3};
password(_Other) -> undefined.

check_password(Username, Password) ->
    case password(Username) of
        {Password, Opaque} ->
            {true, Opaque};
        _Other ->
            false
    end.

verify_auth_2_test_() ->
    [ ?_assertError(_, verify_auth(<<"Basic ", (base64:encode("xyz"))/bytes>>, fun password/1)),
      fun() ->
              {false, ResHeader} =
                  verify_auth(<<"xyz">>, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(ResHeader))
      end,
      fun() ->
              {false, ResHeader} =
                  verify_auth(<<"Basic ", (base64:encode(<<"root:toor">>))/bytes>>, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(ResHeader))
      end,
      ?_assertMatch(
         {true, 2},
         verify_auth(<<"Basic ", (base64:encode(<<"guest:">>))/bytes>>, fun check_password/2)
        ),
      ?_assertMatch(
         {false, _ResHeader},
         verify_auth(<<"Basic ", (base64:encode(<<"guest:123">>))/bytes>>, fun check_password/2)
        ),
      ?_assertMatch(
         {true, 2},
         verify_auth(<<"BaSiC ", (base64:encode(<<"guest:">>))/bytes>>, fun password/1)
        ),
      fun() ->
              Username = <<"xyzzy">>,
              {Password, Opaque} = password(Username),
              ?assertMatch(
                 {true, Opaque},
                 verify_auth(<<"Basic ", (base64:encode(<<Username/bytes, $:, Password/bytes>>))/bytes>>, fun password/1)
                )
      end,
      fun() ->
              {false, ResHeader} =
                  verify_auth(<<"Basic ", (base64:encode(<<"adm:321">>))/bytes>>, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(ResHeader))
      end,
      fun() ->
              {false, ResHeader} =
                  verify_auth(<<"Digest bad,auth,info">>, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(ResHeader))
      end,
      fun() ->
              {false, ResHeader} =
                  verify_auth(undefined, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(ResHeader))
      end,
      fun() ->
              Username = <<"admin">>,
              {false, ResHeader} =
                  verify_auth(["Basic ", base64:encode(<<Username/bytes, $:, "123">>)],
                              fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(ResHeader))
      end ].

verify_auth_3_test_() ->
    [ fun() ->
              {false, ResHeader} =
                  verify_auth(<<"Basic ", (base64:encode(<<"a:b">>))/bytes>>, fun password/1, [{realm, <<"DaRk">>}]),
              ?assertEqual(<<"Basic realm=\"DaRk\"">>, iolist_to_binary(ResHeader))
      end,
      fun() ->
              Username = <<"admin">>,
              {_Password, Opaque} = password(Username),
              ?assertMatch(
                 {true, Opaque},
                 verify_auth(<<"Basic ", (base64:encode(<<"admin:123">>))/bytes>>, fun password/1, [{realm, <<"DaRk">>}])
                )
      end ].

-endif.
