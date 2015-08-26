%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@bestmx.ru>
%%% @doc
%%% Denominative module of the project. Mainly a namespace for types.
%%% @end
%%% For copyright notice see LICENSE.
%%%-------------------------------------------------------------------
-module(ehsa).

%% Types
-export_type([options/0, password/0, password_fun/0, username/0]).

%%%===================================================================
%%% Types
%%%===================================================================

-type username() :: binary().

-type password() :: {digest, _Digest :: binary()} | binary().

-type options() :: [{_Key :: atom(), _Val :: term()}].

-type password_fun() :: fun((_Username :: binary()) ->
                                   {password(), _Opaque :: any()} | undefined).
