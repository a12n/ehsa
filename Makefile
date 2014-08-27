
.PHONY: all app clean distclean doc shell test

ERL ?= erl
REBAR ?= ./rebar

all: $(REBAR)
	$(REBAR) compile

app: $(REBAR)
	$(REBAR) compile skip_deps=true

clean: $(REBAR)
	$(REBAR) clean

distclean: clean
	rm -f doc/*.css doc/*.html doc/*.png doc/edoc-info
	rm -rf .eunit

doc: $(REBAR)
	$(REBAR) doc

rebar:
	wget "https://github.com/rebar/rebar/releases/download/2.5.1/rebar" -O $@
	chmod +x $@

shell:
	$(ERL) -smp -pa ebin/ -pa deps/*/ebin/

test: $(REBAR)
	$(REBAR) eunit
