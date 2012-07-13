%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @copyright (C) 2012, Anton Yabchinskiy
%%% @doc
%%% Utilities for binary strings.
%%% @end
%%%-------------------------------------------------------------------
-module(ehsa_binary).

%% API
-export([format/1, join/2, to_integer/1, to_integer/2, to_lower/1]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Create hexadecimal representation of binary data.
%% @end
%%--------------------------------------------------------------------
-spec format(binary()) -> binary().
format(Data) ->
    << <<(if N >= 10 -> N - 10 + $a; true -> N + $0 end)>> || <<N:4>> <= Data >>.

%%--------------------------------------------------------------------
%% @doc
%% Join binary strings with separator.
%% @end
%%--------------------------------------------------------------------
-spec join([binary() | iolist()], binary() | iolist()) -> binary() | iolist().
join([], _Sep) ->
    <<>>;
join([H], _Sep) ->
    H;
join([H | T], Sep) ->
    [H, Sep, join(T, Sep)].

%%--------------------------------------------------------------------
%% @doc
%% Convert binary string to integer.
%% @end
%%--------------------------------------------------------------------
-spec to_integer(binary()) -> integer().
to_integer(Str) ->
    list_to_integer(binary_to_list(Str)).

%%--------------------------------------------------------------------
%% @doc
%% Convert binary string to integer.
%% @end
%%--------------------------------------------------------------------
-spec to_integer(binary(), 2..36) -> integer().
to_integer(Str, Base) ->
    list_to_integer(binary_to_list(Str), Base).

%%--------------------------------------------------------------------
%% @doc
%% Transform ASCII binary string to lower case.
%% @end
%%--------------------------------------------------------------------
-spec to_lower(binary()) -> binary().
to_lower(Str) ->
    << <<(case Char of
              $A -> $a;
              $B -> $b;
              $C -> $c;
              $D -> $d;
              $E -> $e;
              $F -> $f;
              $G -> $g;
              $H -> $h;
              $I -> $i;
              $J -> $j;
              $K -> $k;
              $L -> $l;
              $M -> $m;
              $N -> $n;
              $O -> $o;
              $P -> $p;
              $Q -> $q;
              $R -> $r;
              $S -> $s;
              $T -> $t;
              $U -> $u;
              $V -> $v;
              $W -> $w;
              $X -> $x;
              $Y -> $y;
              $Z -> $z;
              _C -> Char
          end)>> || <<Char>> <= Str >>.

%%%===================================================================
%%% Tests
%%%===================================================================

-include_lib("eunit/include/eunit.hrl").

-ifdef(TEST).

format_1_test_() ->
    [ ?_test( <<"7f283d85">> = format(<<16#7f, 16#28, 16#3d, 16#85>>) ),
      ?_test( <<"ff">> = format(<<255>>) ),
      ?_test( <<>> = format(<<>>) ) ].

join_2_test_() ->
    [ ?_test( <<"a:b:c">> = iolist_to_binary(join([<<"a">>, <<"b">>, <<"c">>], <<$:>>)) ),
      ?_test( <<>> = iolist_to_binary(join([], <<$,>>)) ),
      ?_test( <<"xyz">> = iolist_to_binary(join([<<"xyz">>], <<$.>>)) ),
      ?_test( <<"e, unit">> = iolist_to_binary(join([<<"e">>, <<"unit">>], <<", ">>)) ) ].

to_integer_1_test_() ->
    [ ?_test( 1 = to_integer(<<"1">>) ),
      ?_test( 13792 = to_integer(<<"13792">>) ),
      ?_assertException(error, badarg, to_integer(<<>>)) ].

to_integer_2_test_() ->
    [ ?_test( 32 = to_integer(<<"20">>, 16) ),
      ?_test( 10 = to_integer(<<"1010">>, 2) ),
      ?_assertException(error, badarg, to_integer(<<>>, 4)) ].

to_lower_1_test_() ->
    [ ?_test( <<>> = to_lower(<<>>) ),
      ?_test( <<"realm">> = to_lower(<<"ReAlM">>) ),
      ?_test( <<"algorithm=md5, username=\"xyz\"">> =
                  to_lower(<<"algorithm=MD5, username=\"Xyz\"">>) ),
      ?_test( <<"abcdefghijklmnopqrstuvwxyz012345,./">> =
                  to_lower(<<"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345,./">>) ) ].

-endif.
