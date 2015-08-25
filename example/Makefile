.PHONY: all app clean shell test

ERL ?= erl
REBAR ?= ../rebar

all:
	$(REBAR) compile

clean:
	$(REBAR) clean

start:
	$(ERL) -smp -pa ebin/ -pa ../ebin/ -pa deps/*/ebin/ -s example
