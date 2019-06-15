## Plugins

This directory structure contains the code that actually performs the testing. This could be used in an external application as a library, and as such should only return results. Nothing in this structure should `print()` or otherwise interact with the console. There is an exception for the `output.debug` method; when used without going through the normal application statup, this call does nothing.

In the future, API documentation will be created to make it easier to leverage the code here in other applications.

### Unit Testing

All methods SHOULD have proper unit testing, including private methods. This is to ensure that we are testing as complete as possible, and as many of these tests may involve interacting with outside services, unit testing of individual private methods allows full coverage without excessive time (or relying too much on the configuration of specific servers).
