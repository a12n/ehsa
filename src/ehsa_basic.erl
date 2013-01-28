%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
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
%% @equiv verify_auth(Req_Header, Pwd_Fun, _Options = [])
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary() | undefined,
                  ehsa:password_fun()) ->
                         {true, ehsa:credentials()} | {false, iodata()}.

verify_auth(Req_Header, Pwd_Fun) ->
    verify_auth(Req_Header, Pwd_Fun, []).

%%--------------------------------------------------------------------
%% @doc
%% Verify basic authentication of HTTP request.
%%
%% `Req_Header' is value of "Authorization" header from client (it may
%% be `undefined').
%%
%% `Pwd_Fun' is a function which, for a given user name, must return
%% either `Password' binary string or `undefined' if there is no such
%% user.
%%
%% `Options' is a list of properties. The available options are:
%% <dl>
%% <dt>`{realm, Realm :: binary()}'</dt>
%% <dd>Binary string `Realm' will be used for realm in "401
%% Unauthorized" responses. If unspecified, it's considered to be empty
%% string.</dd>
%% </dl>
%%
%% Function returns either `{true, Authorized :: credentials()}' if
%% authentication information is valid, or `{false, Res_Header ::
%% iodata()}'. Returned `Res_Header' must be used as a value for
%% 'WWW-Authenticate' header of the response.
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary() | undefined,
                  ehsa:password_fun(),
                  ehsa:options()) ->
                         {true, ehsa:credentials()} | {false, iodata()}.

verify_auth(undefined, Pwd_Fun, Options) ->
    verify_auth(<<>>, Pwd_Fun, Options);

verify_auth(Req_Header, Pwd_Fun, Options) ->
    case binary:split(Req_Header, <<$ >>) of
        [Scheme, Req_Info] ->
            case ehsa_binary:to_lower(Scheme) of
                <<"basic">> ->
                    verify_info(Req_Info, Pwd_Fun, Options);
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
    Res_Header = [ <<"Basic ">>, ehsa_params:format(realm, Realm) ],
    {false, Res_Header}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_info(binary(),
                  ehsa:password_fun(),
                  ehsa:options()) ->
                         {true, ehsa:credentials()} | {false, iodata()}.

verify_info(Req_Info, Pwd_Fun, Options) ->
    [Username, Password] = binary:split(base64:decode(Req_Info), <<$:>>),
    case Pwd_Fun(Username) of
        undefined ->
            unauthorized(Options);
        Password ->
            {true, {Username, Password}}
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

-include_lib("eunit/include/eunit.hrl").

-ifdef(TEST).

password(<<"admin">>) -> <<"123">>;
password(<<"guest">>) -> <<>>;
password(<<"xyzzy">>) -> <<"1,.:235asd\/">>;
password(_Other) -> undefined.

verify_auth_2_test_() ->
    [ ?_assertError(_, verify_auth(<<"Basic ", (base64:encode("xyz"))/bytes>>, fun password/1)),
      fun() ->
              {false, Res_Header} =
                  verify_auth(<<"xyz">>, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(Res_Header))
      end,
      fun() ->
              {false, Res_Header} =
                  verify_auth(<<"Basic ", (base64:encode(<<"root:toor">>))/bytes>>, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(Res_Header))
      end,
      ?_assertMatch(
         {true, {<<"guest">>, <<>>}},
         verify_auth(<<"BaSiC ", (base64:encode(<<"guest:">>))/bytes>>, fun password/1)
        ),
      fun() ->
              Username = <<"xyzzy">>,
              Password = password(Username),
              ?assertMatch(
                 {true, {Username, Password}},
                 verify_auth(<<"Basic ", (base64:encode(<<Username/bytes, $:, Password/bytes>>))/bytes>>, fun password/1)
                )
      end,
      fun() ->
              {false, Res_Header} =
                  verify_auth(<<"Basic ", (base64:encode(<<"adm:321">>))/bytes>>, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(Res_Header))
      end,
      fun() ->
              {false, Res_Header} =
                  verify_auth(<<"Digest bad,auth,info">>, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(Res_Header))
      end,
      fun() ->
              {false, Res_Header} =
                  verify_auth(undefined, fun password/1),
              ?assertEqual(<<"Basic realm=\"\"">>, iolist_to_binary(Res_Header))
      end ].

verify_auth_3_test_() ->
    [ fun() ->
              {false, Res_Header} =
                  verify_auth(<<"Basic ", (base64:encode(<<"a:b">>))/bytes>>, fun password/1, [{realm, <<"DaRk">>}]),
              ?assertEqual(<<"Basic realm=\"DaRk\"">>, iolist_to_binary(Res_Header))
      end,
      fun() ->
              Username = <<"admin">>,
              Password = password(Username),
              ?assertMatch(
                 {true, {Username, Password}},
                 verify_auth(<<"Basic ", (base64:encode(<<"admin:123">>))/bytes>>, fun password/1, [{realm, <<"DaRk">>}])
                )
      end ].

-endif.
