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
    <<"Basic">>.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec init([{atom(), term()}]) -> term().
init(Args) ->
    Realm = proplists:get_value(realm, Args, <<>>),
    {ok, Realm}.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized_info(term()) -> {false, binary() | iolist(), term()}.
unauthorized_info(State = Realm) ->
    {false, ehsa_params:format(realm, Realm), State}.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary(),
                  binary(),
                  ehsa:body(),
                  ehsa:credentials_fun(),
                  term()) ->
                         {true, binary() | iolist() | undefined,
                          ehsa:credentials(), term()} |
                         {false, binary() | iolist(), term()}.
verify_auth(_Method, Req_Info, _Req_Body, Pwd_Fun, State) ->
    [Usr, Pwd] = binary:split(base64:decode(Req_Info), <<$:>>),
    case Pwd_Fun(Usr) of
        {ok, Pwd} ->
            {true, undefined, {Usr, Pwd}, State};
        _Other ->
            unauthorized_info(State)
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

auth_scheme_0_test_() ->
    ?_test( <<"basic">> = ehsa_binary:to_lower(auth_scheme()) ).

init_1_test_() ->
    [ ?_test( {ok, <<>>} = init([]) ),
      ?_test( {ok, <<"Hoom">>} = init([{realm, <<"Hoom">>}]) ) ].

unauthorized_info_1_test_() ->
    [ fun() ->
              {false, Res_Info, <<"Igloo">>} =
                  unauthorized_info(<<"Igloo">>),
              <<"realm=\"Igloo\"">> = iolist_to_binary(Res_Info)
      end ].

verify_auth_5_test_() ->
    Pwd_Fun = fun(<<"admin">>) -> {ok, <<"123">>};
                 (<<"guest">>) -> {ok, <<>>};
                 (<<"xyzzy">>) -> {ok, <<"1,.:235asd\/">>};
                 (_Other) -> undefined
              end,
    Body = <<>>,
    [ ?_assertError(_, verify_auth(<<"GET">>, <<"xyz">>, Body, Pwd_Fun, <<"Uoll">>)),
      ?_assertError(_, verify_auth(<<"PUT">>, base64:encode("xyz"), Body, Pwd_Fun, <<"Wijk">>)),
      fun() ->
              {false, Res_Info, <<"DaRk">>} =
                  verify_auth(<<"GET">>, base64:encode(<<"root:toor">>), Body, Pwd_Fun, <<"DaRk">>),
              <<"realm=\"DaRk\"">> = iolist_to_binary(Res_Info)
      end,
      fun() ->
              {true, undefined, {<<"guest">>, <<>>}, <<"OrDo">>} =
                  verify_auth(<<"PUT">>, base64:encode(<<"guest:">>), Body, Pwd_Fun, <<"OrDo">>)
      end,
      fun() ->
              Creds = {Usr, Pwd} = {<<"xyzzy">>, <<"1,.:235asd\/">>},
              {true, undefined, Creds, <<"Woo">>} =
                  verify_auth(<<"GET">>, base64:encode(<<Usr/bytes, $:, Pwd/bytes>>), Body, Pwd_Fun, <<"Woo">>)
      end,
      fun() ->
              {false, Res_Info, <<>>} =
                  verify_auth(<<"POST">>, base64:encode(<<"adm:321">>), <<"x=1&y=2&z=3">>, Pwd_Fun, <<>>),
              <<"realm=\"\"">> = iolist_to_binary(Res_Info)
      end ].

-endif.
