-module(example_digest_res).

-behaviour(cowboy_http_handler).

%% cowboy_http_handler callbacks
-export([handle/2, init/3, terminate/2]).

%% cowboy_http_rest callbacks
-export([content_types_provided/2, is_authorized/2, rest_init/2, to_text/2]).

%%%===================================================================
%%% cowboy_http_handler callbacks
%%%===================================================================

handle(Req, State) ->
    {ok, Req, State}.

init({_Transport, http}, _Req, _Opts) ->
    {upgrade, protocol, cowboy_http_rest}.

terminate(_Req, _State) ->
    ok.

%%%===================================================================
%%% cowboy_http_rest callbacks
%%%===================================================================

rest_init(Req, _Opts) ->
    {ok, Req, _State = undefined}.

content_types_provided(Req, State) ->
    {[{{<<"text">>, <<"plain">>, []}, to_text}], Req, State}.

is_authorized(Req, State) ->
    {Method, Req_1} = cowboy_http_req:method(Req),
    {Authorization, Req_2} = cowboy_http_req:header('Authorization', Req_1),
    case ehsa_digest:verify_auth(Method, Authorization, fun example_common:password/1) of
        {true, {Username, _Password}} ->
            {true, Req_2, _State = Username};
        {false, Res_Header} ->
            {{false, Res_Header}, Req_2, State}
    end.

to_text(Req, State = Username) ->
    {io_lib:format("Hello, ~s. Server timestamp is ~p.~n", [Username, now()]), Req, State}.
