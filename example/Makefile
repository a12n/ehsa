
.PHONY: all app clean shell test

ERL ?= erl
REBAR ?= ../rebar

all:
	$(REBAR) compile

app:
	$(REBAR) compile skip_deps=true

clean:
	$(REBAR) clean

shell:
	$(ERL) -smp -pa ebin/ -pa ../ebin/ -pa deps/*/ebin/

start:
	$(ERL) -smp -pa ebin/ -pa ../ebin/ -pa deps/*/ebin/ -s example

test:
	$(REBAR) eunit
