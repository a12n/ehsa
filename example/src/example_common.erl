-module(example_common).

%% API
-export([password/1]).

%%%===================================================================
%%% API
%%%===================================================================

password(Username) ->
    All = [ {<<"admin">>, <<"admin01">>},
            {<<"guest">>, <<"">>},
            {<<"xyzzy">>, <<"foo12">>} ],
    case lists:keyfind(Username, 1, All) of
        {Username, Password} ->
            Password;
        _Other ->
            undefined
    end.
