
## Building the Draft

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

This requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/master/doc/SETUP.md).

## Regenerating Test Vectors

After a breaking change in the specification, the test vector script should be
updated accordingly, and used to generate new test vectors.

```sh
$ cd test-vectors
$ go run known-answer-test.go -json >../test-vectors.json
$ go run knwon-answer-test.go -md >../test-vectors.md
```
