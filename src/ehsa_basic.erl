%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_basic).

-behaviour(gen_server).

%% API
-export([start_link/1]).

%% API
-export([unauthorized_info/0, unauthorized_info/1, verify_auth/2,
         verify_auth/3]).

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
-spec start_link([{atom(), term()}]) -> {ok, pid()} | ignore | {error, term()}.
start_link(Args) ->
    case proplists:get_value(register, Args, true) of
        true ->
            gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []);
        false ->
            gen_server:start_link(?MODULE, Args, [])
    end.

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized_info() -> binary() | iolist().
unauthorized_info() ->
    unauthorized_info(?MODULE).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec unauthorized_info(atom() | pid()) -> binary() | iolist().
unauthorized_info(Id) ->
    gen_server:call(Id, unauthorized_info).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary(), ehsa:password_fun()) ->
                         {true, binary() | iolist() | undefined, ehsa:credentials()} |
                         {false, binary() | iolist()}.
verify_auth(Req_Header, Pwd_Fun) ->
    verify_auth(?MODULE, Req_Header, Pwd_Fun).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(atom() | pid(), binary(), ehsa:password_fun()) ->
                         {true, binary() | iolist() | undefined, ehsa:credentials()} |
                         {false, binary() | iolist()}.
verify_auth(Id, Req_Header, Pwd_Fun) ->
    gen_server:call(Id, {verify_auth, Req_Header, Pwd_Fun}).

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
handle_call(unauthorized_info, _From, State = Res_Header) ->
    {reply, Res_Header, State};
handle_call({verify_auth, Req_Header, Pwd_Fun}, _From, State = Res_Header) ->
    [Scheme, Req_Info] = binary:split(Req_Header, <<$ >>),
    Reply =
        case ehsa_binary:to_lower(Scheme) of
            <<"basic">> ->
                [Usr, Pwd] = binary:split(base64:decode(Req_Info), <<$:>>),
                case Pwd_Fun(Usr) of
                    {ok, Pwd} ->
                        {true, undefined, {Usr, Pwd}};
                    _Other ->
                        {false, Res_Header}
                end;
            _Other ->
                {false, Res_Header}
        end,
    {reply, Reply, State};
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
handle_cast(stop, State) ->
    {stop, normal, State};
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
-spec init([{atom(), term()}]) -> {ok, term()} | {stop, term()}.
init(Args) ->
    Realm = proplists:get_value(realm, Args, <<>>),
    Res_Header = [<<"Basic ">>, ehsa_params:format(realm, Realm)],
    {ok, Res_Header}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

%% init_1_test_() ->
%%     [ ?_test( {ok, _} = init([]) ),
%%       ?_test( {ok, _} = init([{realm, <<"Hoom">>}]) ) ].
%%
%% unauthorized_info_1_test_() ->
%%     [ fun() ->
%%               {false, Res_Info, <<"Igloo">>} =
%%                   unauthorized_info(<<"Igloo">>),
%%               <<"realm=\"Igloo\"">> = iolist_to_binary(Res_Info)
%%       end ].
%%
%% verify_auth_5_test_() ->
%%     Pwd_Fun = fun(<<"admin">>) -> {ok, <<"123">>};
%%                  (<<"guest">>) -> {ok, <<>>};
%%                  (<<"xyzzy">>) -> {ok, <<"1,.:235asd\/">>};
%%                  (_Other) -> undefined
%%               end,
%%     Body = <<>>,
%%     [ ?_assertError(_, verify_auth(<<"GET">>, <<"xyz">>, Body, Pwd_Fun, <<"Uoll">>)),
%%       ?_assertError(_, verify_auth(<<"PUT">>, base64:encode("xyz"), Body, Pwd_Fun, <<"Wijk">>)),
%%       fun() ->
%%               {false, Res_Info, <<"DaRk">>} =
%%                   verify_auth(<<"GET">>, base64:encode(<<"root:toor">>), Body, Pwd_Fun, <<"DaRk">>),
%%               <<"realm=\"DaRk\"">> = iolist_to_binary(Res_Info)
%%       end,
%%       fun() ->
%%               {true, undefined, {<<"guest">>, <<>>}, <<"OrDo">>} =
%%                   verify_auth(<<"PUT">>, base64:encode(<<"guest:">>), Body, Pwd_Fun, <<"OrDo">>)
%%       end,
%%       fun() ->
%%               Creds = {Usr, Pwd} = {<<"xyzzy">>, <<"1,.:235asd\/">>},
%%               {true, undefined, Creds, <<"Woo">>} =
%%                   verify_auth(<<"GET">>, base64:encode(<<Usr/bytes, $:, Pwd/bytes>>), Body, Pwd_Fun, <<"Woo">>)
%%       end,
%%       fun() ->
%%               {false, Res_Info, <<>>} =
%%                   verify_auth(<<"POST">>, base64:encode(<<"adm:321">>), <<"x=1&y=2&z=3">>, Pwd_Fun, <<>>),
%%               <<"realm=\"\"">> = iolist_to_binary(Res_Info)
%%       end ].

-endif.
