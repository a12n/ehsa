
.PHONY: all app clean distclean shell test

ERL ?= erl
REBAR ?= ./rebar

all:
	$(REBAR) compile

app:
	$(REBAR) compile skip_deps=true

clean:
	$(REBAR) clean

distclean: clean
	rm -rf .eunit

shell:
	$(ERL) -smp -pa ebin/ -pa deps/*/ebin/

test:
	$(REBAR) eunit
