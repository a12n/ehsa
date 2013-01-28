
.PHONY: all app clean distclean doc shell test

ERL ?= erl
REBAR ?= ./rebar

all:
	$(REBAR) compile

app:
	$(REBAR) compile skip_deps=true

clean:
	$(REBAR) clean

distclean: clean
	rm -f doc/*.css doc/*.html doc/*.png doc/edoc-info
	rm -rf .eunit

doc:
	$(REBAR) doc

shell:
	$(ERL) -smp -pa ebin/ -pa deps/*/ebin/

test:
	$(REBAR) eunit
