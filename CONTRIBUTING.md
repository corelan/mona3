# Contributing to mona.py

First of all: thank you.

Mona has always been a practical tool built by and for people who care about understanding processes, memory corruptions, developing exploits, debugging deeply in general, and producing actionable results. 

Contributions are welcome, and this document outlines the expectations for anyone who wants to help move the project forward.

## Core principles

When contributing to mona.py, please keep the following goals in mind:

- Maintain compatibility with both **Python 2 and Python 3**
- Maintain support for both **32-bit and 64-bit** targets
- Ensure code works on **WinDBG and WinDBGX**
- **Immunity Debugger** compatibility is welcome, but it is a nice-to-have, not a hard requirement
- Preserve the spirit of mona: practical functionality, actionable output, and performance-conscious implementation

## Compatibility requirements

### Python 2 and Python 3

All contributed code must be compatible with both Python 2.7.18 and Python 3.9.13.

That means, among other things:

- Be careful with `str` versus `bytes`
- Avoid language features that only exist in one runtime unless they are properly abstracted
- Test code paths that may behave differently between Python 2 and Python 3
- Do not assume implicit conversions will behave the same everywhere

If a feature cannot be implemented cleanly in a Python 2/3 compatible way, it will likely not be accepted.

### 32-bit and 64-bit support

Contributions must work correctly on both 32-bit and 64-bit processes where applicable.

Keep in mind:

- Pointer sizes differ
- Structure layouts and offsets may differ
- Register sets differ
- Address formatting and arithmetic must be architecture-aware

Do not hardcode assumptions that only hold true on x86.

### Debugger support

At minimum, contributions must support:

- WinDBG
- WinDBGX

Compatibility with Immunity Debugger is appreciated, but it is not mandatory.

If a change breaks WinDBG or WinDBGX behavior, it is unlikely to be merged.

## Implementation guidelines

### Do not write PyKD code in `mona.py`. Put it in windbglib.py instead

`mona.py` should not contain debugger-engine-specific PyKD logic. 

Keep debugger interaction abstracted through the existing framework and helper layers.  
Do not couple core mona functionality directly to PyKD implementation details.

This keeps the codebase cleaner, easier to maintain, and more portable across supported environments.

### Avoid parsing WinDBG command output

Please avoid solutions that rely on executing WinDBG commands and then parsing their textual output.

Prefer direct programmatic access to data structures, debugger APIs, or existing abstractions whenever possible.

If something feels easier to do by scraping debugger output, it is usually worth taking a step back and finding a more robust way.

## When in doubt

If you are unsure about how something should be implemented, or you want to discuss an approach before spending time on it:

Head over to the [Corelan Discord Server](https://discord.gg/JdqQcxAqcn) and ask in the **#mona** channel.

That is the preferred place to ask questions, validate design decisions, and discuss implementation details before opening a pull request.

## Contribution workflow

### 1. Create a branch

Do your work in a dedicated branch.

Please do not work directly on the main branch.

### 2. Make focused changes

Try to keep pull requests focused and easy to review.

A good pull request usually:

- solves one problem
- adds one feature
- or performs one logical refactor

Large mixed PRs are harder to review and harder to merge.

### 3. Test your changes

Before submitting, test as much as reasonably possible:

- Python 2 and Python 3
- 32-bit and 64-bit scenarios
- WinDBG and WinDBGX

If your code touches architecture-specific or debugger-specific behavior, extra validation is expected.

For targeted manual testing of a single `!mona` command across the main supported combinations, you can use [`testing/runmonatests.cmd`](testing/runmonatests.cmd). The script runs the command in 6 scenarios:

- x86 + Python 3.9
- x64 + Python 3.9
- x86 + Python 2.7
- x64 + Python 2.7
- x86 + WinDbgX + Python 3.9
- x64 + WinDbgX + Python 3.9

Usage:

```bat
testing\runmonatests.cmd !mona modules
testing\runmonatests.cmd !mona rop -m kernel32.dll
```

Before using it, open the file and adjust the paths and settings for your local setup, especially `MONA_PATH`, `TARGET_APP_32`, `TARGET_APP_64`, and `DEBUGGER_FRONTEND`. If you prefer console execution, set `AUTO_QUIT=1` and use `DEBUGGER_FRONTEND=cdb`.
Run the script from an elevated Administrator Command Prompt so WinDbg and the target process can start with the required permissions.

### 4. Submit a pull request

Once your branch is ready, open a PR.

Please include:

- a clear description of the problem being solved
- a summary of the approach
- any limitations or known caveats
- notes about what was tested

### 5. Resolve merge conflicts

If your PR develops merge conflicts, please resolve them before asking for final review.

Keeping your branch merge-ready helps a lot and makes review smoother for everyone.

## Style expectations

A few general expectations:

- Write clear, readable code. Document your code
- Prefer maintainability over cleverness
- Reuse existing helpers and abstractions where appropriate
- Keep performance in mind, especially in routines that process large result sets or scan memory extensively
- Avoid introducing debugger-specific shortcuts into generic logic
- Try to preserve existing behavior unless the change intentionally improves it

## Final note

Mona is used in real debugging and exploit development workflows.  
That means correctness, portability, and robustness matter.

Please build with care.

Thank you for contributing.
