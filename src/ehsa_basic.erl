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
%% either `{ok, Password}' or `undefined' if there is no such user.
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
        {ok, Password} ->
            {true, {Username, Password}};
        _Other ->
            unauthorized(Options)
    end.
