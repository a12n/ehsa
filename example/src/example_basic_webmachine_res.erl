-module(example_basic_webmachine_res).

%% API
-export([allowed_methods/2, content_types_provided/2, init/1,
         is_authorized/2, process_get/2]).

-include_lib("webmachine/include/webmachine.hrl").

%%%===================================================================
%%% API
%%%===================================================================

allowed_methods(Req, Context) ->
    {['GET'], Req, Context}.

content_types_provided(Req, Context) ->
    {[{"text/plain", process_get}], Req, Context}.

init(_Args) ->
    {ok, _Context = undefined}.

is_authorized(Req, Context) ->
    Authorization = wrq:get_req_header("Authorization", Req),
    case ehsa_basic:verify_auth(Authorization, fun example_common:password/1) of
        {true, _Opaque = Username} ->
            {true, Req, _Context = Username};
        {false, ResHeader} ->
            {ResHeader, Req, Context}
    end.

process_get(Req, Context = Username) ->
    {io_lib:format("Hello, ~s. Server timestamp is ~p.~n", [Username, now()]), Req, Context}.
