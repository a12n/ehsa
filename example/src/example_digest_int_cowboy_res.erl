-module(example_digest_int_cowboy_res).

%% cowboy_http_handler callbacks
-export([init/3]).

%% cowboy_http_rest callbacks
-export([content_types_provided/2, is_authorized/2, rest_init/2, to_text/2]).

%%%===================================================================
%%% cowboy_http_handler callbacks
%%%===================================================================

init({_Transport, http}, _Req, _Opts) ->
    {upgrade, protocol, cowboy_http_rest}.

%%%===================================================================
%%% cowboy_http_rest callbacks
%%%===================================================================

rest_init(Req, _Opts) ->
    {ok, Req, _State = undefined}.

content_types_provided(Req, State) ->
    {[{{<<"text">>, <<"plain">>, []}, to_text}], Req, State}.

is_authorized(Req, State) ->
    {Method, Req_1} = cowboy_req:method(Req),
    {Authorization, Req_2} = cowboy_req:header(<<"authorization">>, Req_1),
    {Body, Req_3} =
        case cowboy_req:body(Req_2) of
            {ok, _1, _2} ->
                {_1, _2};
            {error, badarg} ->
                {<<>>, Req_2}
        end,
    case ehsa_digest:verify_auth_int(Method, Authorization, Body, fun example_common:password/1) of
        {true, _Opaque = Username} ->
            {true, Req_3, _State = Username};
        {false, Res_Header} ->
            {{false, Res_Header}, Req_3, State}
    end.

to_text(Req, State = Username) ->
    {io_lib:format("Hello, ~s. Server timestamp is ~p.~n", [Username, now()]), Req, State}.
