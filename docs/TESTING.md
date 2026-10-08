# Test layout and verification

Paths below are relative to the plugin root. Run tests in a disposable Cordova
test host containing this plugin; never use production credentials.

## JavaScript bridge tests

With Node.js and Mocha available in your development toolchain, run from the
plugin root:

```sh
pnpm exec mocha --no-config tests/js/bridge.test.js
```

These tests load the shipped www bridge with mocked Cordova callbacks. They
check JavaScript contracts and do not execute Android or iOS cryptography.

## Android and iOS

- tests/android/ contains Android instrumentation sources. Configure the test
  host with Cordova, the plugin and AndroidX test dependencies, and add these
  sources to its androidTest source set. Build and execute the selected
  instrumentation suite on an emulator or device.
- tests/ios/ contains XCTest sources and test support. Configure a Cordova test
  host and the required support module in Xcode, include the plugin sources and
  run the selected suite on macOS with a simulator or device.

The package provides test sources, not a standalone Gradle/Xcode test project or
application-level runner commands. Check the imports and support files when
configuring your host. Compilation and test-source preparation are not proof of
execution. Run validation jobs serially.

Java host suites in tests/native/ require Cordova/Android test doubles and
platform dependencies supplied by the harness. They do not run directly with
Mocha. Preserve vector, boundary and failure-path coverage during changes.

Streaming File results also require cordova-plugin-file in the test host. The Go
reference in tests/reference/main.go reads the bundled vector file:

```sh
go run tests/reference/main.go
```

Use Go 1.27 or later. The optional --write flag regenerates fixtures and must
only be used when intentionally updating reviewed protocol vectors.

See [README security results](../README.md#security) for recorded validation and
its limits, and [DEVELOPMENT.md](../DEVELOPMENT.md) for native invariants.
