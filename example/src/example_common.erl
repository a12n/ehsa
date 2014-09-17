-module(example_common).

%% API
-export([password/1]).

%%%===================================================================
%%% API
%%%===================================================================

password(Username) ->
    All = [ {<<"admin">>, {digest, <<"e2a66f6c78d0e132f227453dfa25559f">>}},
            {<<"guest">>, <<"">>},
            {<<"xyzzy">>, <<"foo12">>} ],
    case lists:keyfind(Username, 1, All) of
        {Username, Password} ->
            {Password, _Opaque = Username};
        _Other ->
            undefined
    end.
