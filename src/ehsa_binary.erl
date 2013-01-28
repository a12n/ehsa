%%%-------------------------------------------------------------------
%%% @author Anton Yabchinskiy <arn@users.berlios.de>
%%% @doc
%%% Utilities for binary strings.
%%% @end
%%% For copyright notice see LICENSE.
%%%-------------------------------------------------------------------
-module(ehsa_binary).

%% API
-export([decode/1, encode/1, join/2, to_integer/1, to_integer/2,
         to_lower/1]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Decode binary from hexadecimal representation.
%% @end
%%--------------------------------------------------------------------
-spec decode(binary()) -> binary().

decode(Hex) ->
    << <<(case H of
              $0 -> 0;
              $1 -> 1;
              $2 -> 2;
              $3 -> 3;
              $4 -> 4;
              $5 -> 5;
              $6 -> 6;
              $7 -> 7;
              $8 -> 8;
              $9 -> 9;
              $A -> 10;
              $B -> 11;
              $C -> 12;
              $D -> 13;
              $E -> 14;
              $F -> 15;
              $a -> 10;
              $b -> 11;
              $c -> 12;
              $d -> 13;
              $e -> 14;
              $f -> 15
          end):4>> || <<H>> <= Hex >>.

%%--------------------------------------------------------------------
%% @doc
%% Create hexadecimal representation of binary data. Result is
%% guaranteed to be in lower case.
%% @end
%%--------------------------------------------------------------------
-spec encode(binary()) -> binary().

encode(Bin) ->
    << <<(if B >= 10 -> B - 10 + $a; true -> B + $0 end)>> || <<B:4>> <= Bin >>.

%%--------------------------------------------------------------------
%% @doc
%% Join binary strings with separator.
%% @end
%%--------------------------------------------------------------------
-spec join([iodata()], iodata()) -> iodata().

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

decode_1_test_() ->
    [ ?_test( <<1, 2, 3, 4>> = decode(<<"01020304">>) ),
      ?_test( <<1, 2:4>> = decode(<<"012">>) ),
      ?_test( <<16#7f, 16#28, 16#3d, 16#85>> = decode(<<"7f283D85">>) ),
      ?_test( <<16#a, 16#b, 16#c, 16#d, 16#e, 16#f>> = decode(<<"0a0B0c0D0e0F">>) ),
      ?_test( <<>> = decode(<<>>) ),
      ?_test( <<10, 12, 14>> = decode(<<"0A0C0E">>) ),
      ?_test( <<1, 16#23, 16#45, 16#67, 16#89, 16#ab, 16#cd, 16#ef>> = decode(<<"0123456789aBcDeF">>) ),
      ?_assertError(_, decode(<<"abcdefghijkl">>)) ].

encode_1_test_() ->
    [ ?_test( <<"7f283d85">> = encode(<<16#7f, 16#28, 16#3d, 16#85>>) ),
      ?_test( <<"ff">> = encode(<<255>>) ),
      ?_test( <<"012">> = encode(<<1, 2:4>>) ),
      ?_test( <<>> = encode(<<>>) ) ].

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
