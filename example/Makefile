.PHONY: all app clean distclean start

REBAR ?= ../rebar3

all:
	$(REBAR) compile

clean:
	$(REBAR) clean

distclean: clean
	rm -rf _build/

start:
	$(REBAR) shell --apps example
