-module(example_basic_cowboy_res).

%% cowboy_http_handler callbacks
-export([init/3]).

%% cowboy_http_rest callbacks
-export([content_types_provided/2, is_authorized/2, rest_init/2, to_text/2]).

%%%===================================================================
%%% cowboy_http_handler callbacks
%%%===================================================================

init({_Transport, http}, _Req, _Opts) ->
    {upgrade, protocol, cowboy_rest}.

%%%===================================================================
%%% cowboy_http_rest callbacks
%%%===================================================================

rest_init(Req, _Opts) ->
    {ok, Req, _State = undefined}.

content_types_provided(Req, State) ->
    {[{{<<"text">>, <<"plain">>, []}, to_text}], Req, State}.

is_authorized(Req, State) ->
    {Authorization, Req_1} = cowboy_req:header(<<"authorization">>, Req),
    case ehsa_basic:verify_auth(Authorization, fun example_common:password/1) of
        {true, _Opaque = Username} ->
            {true, Req_1, _State = Username};
        {false, Res_Header} ->
            {{false, Res_Header}, Req_1, State}
    end.

to_text(Req, State = Username) ->
    {io_lib:format("Hello, ~s. Server timestamp is ~p.~n", [Username, now()]), Req, State}.
