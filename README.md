# Cryptopals Crypto Challenge Solutions

These are my attempts at the [cryptopals crypto challenges](https://cryptopals.com/).

## Quickstart
To run all tests:
```
make test
```
Add debugging as you'd like with pdb, pudb, ipdb, etc. to explore the code.

### To add new set, add them to the Makefile:
```make
# Makefile
sets:= set1 set2 foo
challenges_set_foo:= $(patsubst %, set_foo-%, 1 2 bar)
```

Then add the recipes:
```make
.PHONY: test-foo
test-foo: $(challenges_set_foo);

set_foo-%: venv
	./venv/bin/python -m foo_package.bar_$*
```

This example will execute the following python modules:
- `foo_package.bar_1`
- `foo_package.bar_2`
- `foo_package.bar_bar`
