%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@bestmx.ru>
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

-type username() :: binary().

-type password() :: {digest, _Digest :: binary()} | binary().

-type credentials() :: {username(), password()}.

-type options() :: [{_Key :: atom(), _Val :: term()}].

-type password_fun() :: fun((_Username :: binary()) ->
                                   password() | undefined).
