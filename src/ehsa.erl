%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @doc
%%% Denominative module of the project. Mainly a namespace for types.
%%% @end
%%% For copyright notice see LICENSE.
%%%-------------------------------------------------------------------
-module(ehsa).

%% Types
-export_type([credentials/0, options/0, password_fun/0]).

%%%===================================================================
%%% Types
%%%===================================================================

-type credentials() :: {_Username :: binary(),
                        _Password :: binary()}.

-type options() :: [{_Key :: atom(), _Val :: term()}].

-type password_fun() :: fun((_Username :: binary()) ->
                                   {ok, _Password :: binary()} |
                                   undefined).
