.PHONY: all clean distclean doc shell test

REBAR ?= ./rebar3

all: $(REBAR)
	$(REBAR) compile

clean: $(REBAR)
	$(REBAR) clean

distclean: clean
	rm -rf _build/ doc/ rebar3

doc: $(REBAR)
	$(REBAR) edoc

shell: $(REBAR)
	$(REBAR) shell

test: $(REBAR)
	$(REBAR) eunit
	$(REBAR) cover

rebar3:
	wget "https://github.com/erlang/rebar3/releases/download/3.3.1/rebar3" -O $@
	chmod +x $@
