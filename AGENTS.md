# Project-Specific Guidance for AI Assistants

Rules are described in terms of [rfc/2119].

All agents MUST respect the guidance in this file. Whenever you start a new
task and read these rules, you MUST confirm in your output that you have followed
them. You MAY ask to deviate from them, but you MUST NOT ignore them, and you
MUST provide justification for doing so and obtain clear and positive approval
from a human to do so.

Humans SHOULD also abide by this guidance.


## Design

Any build, test, and validation, that are added to CI/CD automation SHOULD be
repeatable in a development environment. It SHOULD also be easy and obvious how
to run all checks individually and as one command.


## Verification

You MUST verify your changes locally before finalizing a task or submitting an
implementation. To determine what this means, read all the tasks from CI/CD automation.
Skip any that are for setup and caching. If any step reports warnings or errors,
resolve them before completing the task.


## References

[rfc/2119]: https://datatracker.ietf.org/doc/html/rfc2119
