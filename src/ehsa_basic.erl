%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%%
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_basic).

%% API
-export([verify_auth/2, verify_auth/3]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec verify_auth(binary() | undefined,
                  ehsa:password_fun()) ->
                         {true, ehsa:credentials()} | {false, iodata()}.

verify_auth(Req_Header, Pwd_Fun) ->
    verify_auth(Req_Header, Pwd_Fun, []).

%%--------------------------------------------------------------------
%% @doc
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
        {ok, Password} ->
            {true, {Username, Password}};
        _Other ->
            unauthorized(Options)
    end.
