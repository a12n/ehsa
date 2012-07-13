-module(ehsa_params_parser).
-export([parse/1,file/1]).
-compile(nowarn_unused_vars).
-compile({nowarn_unused_function,[p/4, p/5, p_eof/0, p_optional/1, p_not/1, p_assert/1, p_seq/1, p_and/1, p_choose/1, p_zero_or_more/1, p_one_or_more/1, p_label/2, p_string/1, p_anything/0, p_charclass/1, p_attempt/4, line/1, column/1]}).



-spec file(file:name()) -> any().
file(Filename) -> {ok, Bin} = file:read_file(Filename), parse(Bin).

-spec parse(binary() | list()) -> any().
parse(List) when is_list(List) -> parse(list_to_binary(List));
parse(Input) when is_binary(Input) ->
  setup_memo(),
  Result = case 'auth_params'(Input,{{line,1},{column,1}}) of
             {AST, <<>>, _Index} -> AST;
             Any -> Any
           end,
  release_memo(), Result.

'auth_params'(Input, Index) ->
  p(Input, Index, 'auth_params', fun(I,D) -> (p_seq([p_optional(fun 'sp'/2), fun 'auth_param'/2, p_zero_or_more(p_seq([p_optional(fun 'lws'/2), p_string(<<",">>), p_optional(fun 'lws'/2), fun 'auth_param'/2])), p_optional(fun 'ws'/2)]))(I,D) end, fun(Node, Idx) -> [lists:nth(2, Node) | [lists:nth(4, Item) || Item <- lists:nth(3, Node)]] end).

'auth_param'(Input, Index) ->
  p(Input, Index, 'auth_param', fun(I,D) -> (p_choose([fun 'realm'/2, fun 'nonce'/2, fun 'opaque'/2, fun 'algorithm'/2, fun 'username'/2, fun 'digest_uri'/2, fun 'message_qop'/2, fun 'cnonce'/2, fun 'nonce_count'/2, fun 'response'/2, fun 'gen_auth_param'/2]))(I,D) end, fun(Node, Idx) -> Node end).

'realm'(Input, Index) ->
  p(Input, Index, 'realm', fun(I,D) -> (p_seq([p_string(<<"realm">>), p_string(<<"=">>), fun 'quoted_string'/2]))(I,D) end, fun(Node, Idx) -> {realm, lists:nth(3, Node)} end).

'nonce'(Input, Index) ->
  p(Input, Index, 'nonce', fun(I,D) -> (p_seq([p_string(<<"nonce">>), p_string(<<"=">>), fun 'quoted_string'/2]))(I,D) end, fun(Node, Idx) -> {nonce, lists:nth(3, Node)} end).

'opaque'(Input, Index) ->
  p(Input, Index, 'opaque', fun(I,D) -> (p_seq([p_string(<<"opaque">>), p_string(<<"=">>), fun 'quoted_string'/2]))(I,D) end, fun(Node, Idx) -> {opaque, lists:nth(3, Node)} end).

'algorithm'(Input, Index) ->
  p(Input, Index, 'algorithm', fun(I,D) -> (p_seq([p_string(<<"algorithm">>), p_string(<<"=">>), p_choose([fun 'algorithm_value'/2, fun 'token'/2])]))(I,D) end, fun(Node, Idx) -> {algorithm, lists:nth(3, Node)} end).

'algorithm_value'(Input, Index) ->
  p(Input, Index, 'algorithm_value', fun(I,D) -> (p_choose([p_string(<<"MD5-sess">>), p_string(<<"MD5">>)]))(I,D) end, fun(Node, Idx) -> case iolist_to_binary(Node) of
     <<"MD5-sess">> -> md5_sess;
     <<"MD5">>      -> md5
 end end).

'qop_value'(Input, Index) ->
  p(Input, Index, 'qop_value', fun(I,D) -> (p_choose([p_string(<<"auth-int">>), p_string(<<"auth">>)]))(I,D) end, fun(Node, Idx) -> case iolist_to_binary(Node) of
     <<"auth-int">> -> auth_int;
     <<"auth">>     -> auth
 end end).

'username'(Input, Index) ->
  p(Input, Index, 'username', fun(I,D) -> (p_seq([p_string(<<"username">>), p_string(<<"=">>), fun 'quoted_string'/2]))(I,D) end, fun(Node, Idx) -> {username, lists:nth(3, Node)} end).

'digest_uri'(Input, Index) ->
  p(Input, Index, 'digest_uri', fun(I,D) -> (p_seq([p_string(<<"uri">>), p_string(<<"=">>), p_string(<<"\"">>), fun 'request_uri'/2, p_string(<<"\"">>)]))(I,D) end, fun(Node, Idx) -> {uri, lists:nth(4, Node)} end).

'message_qop'(Input, Index) ->
  p(Input, Index, 'message_qop', fun(I,D) -> (p_seq([p_string(<<"qop">>), p_string(<<"=">>), p_choose([fun 'qop_value'/2, fun 'token'/2])]))(I,D) end, fun(Node, Idx) -> {qop, lists:nth(3, Node)} end).

'cnonce'(Input, Index) ->
  p(Input, Index, 'cnonce', fun(I,D) -> (p_seq([p_string(<<"cnonce">>), p_string(<<"=">>), fun 'quoted_string'/2]))(I,D) end, fun(Node, Idx) -> {cnonce, lists:nth(3, Node)} end).

'nonce_count'(Input, Index) ->
  p(Input, Index, 'nonce_count', fun(I,D) -> (p_seq([p_string(<<"nc">>), p_string(<<"=">>), fun 'nc_value'/2]))(I,D) end, fun(Node, Idx) -> {nc, lists:nth(3, Node)} end).

'nc_value'(Input, Index) ->
  p(Input, Index, 'nc_value', fun(I,D) -> (p_seq([fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2]))(I,D) end, fun(Node, Idx) -> list_to_integer(binary_to_list(iolist_to_binary(Node)), 16) end).

'response'(Input, Index) ->
  p(Input, Index, 'response', fun(I,D) -> (p_seq([p_string(<<"response">>), p_string(<<"=">>), p_string(<<"\"">>), fun 'response_digest'/2, p_string(<<"\"">>)]))(I,D) end, fun(Node, Idx) -> {response, ehsa_binary:to_lower(lists:nth(4, Node))} end).

'response_digest'(Input, Index) ->
  p(Input, Index, 'response_digest', fun(I,D) -> (p_seq([fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2, fun 'hex'/2]))(I,D) end, fun(Node, Idx) -> iolist_to_binary(Node) end).

'hex'(Input, Index) ->
  p(Input, Index, 'hex', fun(I,D) -> (p_charclass(<<"[0-9A-Fa-f]">>))(I,D) end, fun(Node, Idx) -> Node end).

'gen_auth_param'(Input, Index) ->
  p(Input, Index, 'gen_auth_param', fun(I,D) -> (p_seq([fun 'token'/2, p_string(<<"=">>), p_choose([fun 'token'/2, fun 'quoted_string'/2])]))(I,D) end, fun(Node, Idx) -> {lists:nth(1, Node), lists:nth(3, Node)} end).

'token'(Input, Index) ->
  p(Input, Index, 'token', fun(I,D) -> (p_one_or_more(p_charclass(<<"[-!#$%&´*+0-9A-Z^_`a-z|~]">>)))(I,D) end, fun(Node, Idx) -> iolist_to_binary(Node) end).

'quoted_string'(Input, Index) ->
  p(Input, Index, 'quoted_string', fun(I,D) -> (p_seq([p_string(<<"\"">>), p_zero_or_more(p_seq([p_not(p_string(<<"\"">>)), p_choose([p_string(<<"\\\\">>), p_string(<<"\\\"">>), p_anything()])])), p_string(<<"\"">>)]))(I,D) end, fun(Node, Idx) -> iolist_to_binary(lists:nth(2, Node)) end).

'request_uri'(Input, Index) ->
  p(Input, Index, 'request_uri', fun(I,D) -> (p_one_or_more(p_charclass(<<"[-#%&*+0-9A-Z_a-z~:\/?]">>)))(I,D) end, fun(Node, Idx) -> iolist_to_binary(Node) end).

'sp'(Input, Index) ->
  p(Input, Index, 'sp', fun(I,D) -> (p_one_or_more(p_string(<<"\s">>)))(I,D) end, fun(Node, Idx) -> Node end).

'ws'(Input, Index) ->
  p(Input, Index, 'ws', fun(I,D) -> (p_one_or_more(p_charclass(<<"[\s\t]">>)))(I,D) end, fun(Node, Idx) -> Node end).

'crlf'(Input, Index) ->
  p(Input, Index, 'crlf', fun(I,D) -> (p_string(<<"\r\n">>))(I,D) end, fun(Node, Idx) -> Node end).

'lws'(Input, Index) ->
  p(Input, Index, 'lws', fun(I,D) -> (p_seq([p_optional(fun 'crlf'/2), p_one_or_more(p_choose([p_string(<<"\s">>), p_string(<<"\t">>)]))]))(I,D) end, fun(Node, Idx) -> Node end).




p(Inp, Index, Name, ParseFun) ->
  p(Inp, Index, Name, ParseFun, fun(N, _Idx) -> N end).

p(Inp, StartIndex, Name, ParseFun, TransformFun) ->
  case get_memo(StartIndex, Name) of      % See if the current reduction is memoized
    {ok, Memo} -> %Memo;                     % If it is, return the stored result
      Memo;
    _ ->                                        % If not, attempt to parse
      Result = case ParseFun(Inp, StartIndex) of
        {fail,_} = Failure ->                       % If it fails, memoize the failure
          Failure;
        {Match, InpRem, NewIndex} ->               % If it passes, transform and memoize the result.
          Transformed = TransformFun(Match, StartIndex),
          {Transformed, InpRem, NewIndex}
      end,
      memoize(StartIndex, Name, Result),
      Result
  end.

setup_memo() ->
  put(parse_memo_table, ets:new(?MODULE, [set])).

release_memo() ->
  ets:delete(memo_table_name()).

memoize(Index, Name, Result) ->
  Memo = case ets:lookup(memo_table_name(), Index) of
              [] -> [];
              [{Index, Plist}] -> Plist
         end,
  ets:insert(memo_table_name(), {Index, [{Name, Result}|Memo]}).

get_memo(Index, Name) ->
  case ets:lookup(memo_table_name(), Index) of
    [] -> {error, not_found};
    [{Index, Plist}] ->
      case proplists:lookup(Name, Plist) of
        {Name, Result}  -> {ok, Result};
        _  -> {error, not_found}
      end
    end.

memo_table_name() ->
    get(parse_memo_table).

p_eof() ->
  fun(<<>>, Index) -> {eof, [], Index};
     (_, Index) -> {fail, {expected, eof, Index}} end.

p_optional(P) ->
  fun(Input, Index) ->
      case P(Input, Index) of
        {fail,_} -> {[], Input, Index};
        {_, _, _} = Success -> Success
      end
  end.

p_not(P) ->
  fun(Input, Index)->
      case P(Input,Index) of
        {fail,_} ->
          {[], Input, Index};
        {Result, _, _} -> {fail, {expected, {no_match, Result},Index}}
      end
  end.

p_assert(P) ->
  fun(Input,Index) ->
      case P(Input,Index) of
        {fail,_} = Failure-> Failure;
        _ -> {[], Input, Index}
      end
  end.

p_and(P) ->
  p_seq(P).

p_seq(P) ->
  fun(Input, Index) ->
      p_all(P, Input, Index, [])
  end.

p_all([], Inp, Index, Accum ) -> {lists:reverse( Accum ), Inp, Index};
p_all([P|Parsers], Inp, Index, Accum) ->
  case P(Inp, Index) of
    {fail, _} = Failure -> Failure;
    {Result, InpRem, NewIndex} -> p_all(Parsers, InpRem, NewIndex, [Result|Accum])
  end.

p_choose(Parsers) ->
  fun(Input, Index) ->
      p_attempt(Parsers, Input, Index, none)
  end.

p_attempt([], _Input, _Index, Failure) -> Failure;
p_attempt([P|Parsers], Input, Index, FirstFailure)->
  case P(Input, Index) of
    {fail, _} = Failure ->
      case FirstFailure of
        none -> p_attempt(Parsers, Input, Index, Failure);
        _ -> p_attempt(Parsers, Input, Index, FirstFailure)
      end;
    Result -> Result
  end.

p_zero_or_more(P) ->
  fun(Input, Index) ->
      p_scan(P, Input, Index, [])
  end.

p_one_or_more(P) ->
  fun(Input, Index)->
      Result = p_scan(P, Input, Index, []),
      case Result of
        {[_|_], _, _} ->
          Result;
        _ ->
          {fail, {expected, Failure, _}} = P(Input,Index),
          {fail, {expected, {at_least_one, Failure}, Index}}
      end
  end.

p_label(Tag, P) ->
  fun(Input, Index) ->
      case P(Input, Index) of
        {fail,_} = Failure ->
           Failure;
        {Result, InpRem, NewIndex} ->
          {{Tag, Result}, InpRem, NewIndex}
      end
  end.

p_scan(_, [], Index, Accum) -> {lists:reverse( Accum ), [], Index};
p_scan(P, Inp, Index, Accum) ->
  case P(Inp, Index) of
    {fail,_} -> {lists:reverse(Accum), Inp, Index};
    {Result, InpRem, NewIndex} -> p_scan(P, InpRem, NewIndex, [Result | Accum])
  end.

p_string(S) when is_list(S) -> p_string(list_to_binary(S));
p_string(S) ->
    Length = erlang:byte_size(S),
    fun(Input, Index) ->
      try
          <<S:Length/binary, Rest/binary>> = Input,
          {S, Rest, p_advance_index(S, Index)}
      catch
          error:{badmatch,_} -> {fail, {expected, {string, S}, Index}}
      end
    end.

p_anything() ->
  fun(<<>>, Index) -> {fail, {expected, any_character, Index}};
     (Input, Index) when is_binary(Input) ->
          <<C/utf8, Rest/binary>> = Input,
          {<<C/utf8>>, Rest, p_advance_index(<<C/utf8>>, Index)}
  end.

p_charclass(Class) ->
    {ok, RE} = re:compile(Class, [unicode, dotall]),
    fun(Inp, Index) ->
            case re:run(Inp, RE, [anchored]) of
                {match, [{0, Length}|_]} ->
                    {Head, Tail} = erlang:split_binary(Inp, Length),
                    {Head, Tail, p_advance_index(Head, Index)};
                _ -> {fail, {expected, {character_class, binary_to_list(Class)}, Index}}
            end
    end.

line({{line,L},_}) -> L;
line(_) -> undefined.

column({_,{column,C}}) -> C;
column(_) -> undefined.

p_advance_index(MatchedInput, Index) when is_list(MatchedInput) orelse is_binary(MatchedInput)-> % strings
  lists:foldl(fun p_advance_index/2, Index, unicode:characters_to_list(MatchedInput));
p_advance_index(MatchedInput, Index) when is_integer(MatchedInput) -> % single characters
  {{line, Line}, {column, Col}} = Index,
  case MatchedInput of
    $\n -> {{line, Line+1}, {column, 1}};
    _ -> {{line, Line}, {column, Col+1}}
  end.
