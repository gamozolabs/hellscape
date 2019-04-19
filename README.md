# Hellscape

This is a tool for validating feedback is working as expected in my vectorized emulator. But it could work in really any tool with code coverage.

This tool has multiple bugs which can all be found with varying levels of coverage and feedback in a fully dynamic fuzzer.

It is expected that my vectorized emulator can find all 6 of these bugs in less than a second, and it is used for regression testing of my coverage based feedback.

# Disclaimer

This is a playground for testing your tool. If you cheat your way through, congrats, you're just wasting your own time. It's important to note that the constraints here are only for validation of your tool, and not realistic for real fuzzing. If you _ever_ have prior knowledge to enlighten a fuzzer with (eg. strings, formats of a protocol, etc), you are _always_ better off passing that through. Full reconstruction of a protocol is pointless if you can just inform the fuzzer with that knowledge in the first place.

# Rules

The way I use this requires I follow some rules that I'm not cheating.

- No static analysis (no symbolic, no taint tracking, dependency chain analysis, etc)
- Nothing beyond pure-random mutations on previous inputs (byteflips only, no `strings` from the binary allowed for injection)
- Initial input corupus must be empty (no pre-seeding with inputs)
- No knowledge/special casing of functions (like the memcmp) allowed. The existance of a memcmp must be black-box to the fuzzer

# Workflow

- Start off fuzzing with an input filled with zeros
- Mutate by picking a random amount of bytes in it to randomly change
- On dynamically observed events (new coverage, register state, etc) save the input that caused them
- 10: Start a new fuzz case, grab a previous input saved from the step above
- Mutate by picking a random amount of bytes in it to randomly change
- Goto 10

No other analysis of the program allowed, and no other mutation/fuzzing strategies allowed. This is only to stress the gathering of unique coverage events to stress when we "save" events.

# Goal

Find all 6 bugs in hellscape with a dumb fuzzer that _only_ does byte flips on previous inputs.

## Cheesing it

This program is simple enough that you can cheese it by gathering massively verbose coverage. But you're just really cheating yourself out of a realistic solution that scales to larger targets with 100k+ blocks. It's up to you to limit yourself to a realistic solution.

# Bugs in Hellscape

There are 6 bugs in hellscape

## Code-coverage findable bug

This is a simple bug which any any coverage-based fuzzer can find. It compares one byte at a time, where each compare is a unique compare. Meaning each byte "found" will cause a new coverage event. To my knowledge this is the only bug that any traitional tool like AFL could find, as it's the only one that can be found with only coverage.

The input for this crash is `\x00\x00\x00\x00MAGICSTRING`

## Memcmp findable bug

This bug is triggered if a memcmp matches. Since the loop comparing bytes is re-used, simple code coverage will not be adequate here. Something to track loop depth or state of the compare itself is required.

The input for this crash is `\x01\x00\x00\x00mEmCmPsArEhArD`

## Double memcmp findable bug

This bug is triggered if 2 separate memcmps match. This stresses that the state used to track memcmp depth somehow is influenced by call site. This allows feedback from something like `memcmp()` in a real scenario, where it's used by many callers, and the coverage generated in it must be associated with call site.

The input for this crash is `\x02\x00\x00\x00MULTImemcmp()`

## Dword compare findable bug

This bug is triggered if a single 32-bit compare passes. This is to stress that you can gather partial-compare-state (eg. unrolling compares to bytes), such that there is 4x256 compexity rather than 2^32 complexity in finding this bug.

The input for this crash is `\x03\x00\x00\x00\x87\x95\x8f\xea`

## Dword memcmp findable bug

This is comparable to the `memcmp findable bug` but this one has a memcmp which operates on dwords rather than bytes, so it stresses partial-compare feedback here too.

The input for this crash is `\x04\x00\x00\x00aPPl3sta5t3g00d!`

## Dword double memcmp findable bug

This bug is based on 2 dword-unrolled memcmps passing from unique call sites. This is the pinnacle of all the problems in hellscape. It requires per-call-site-loop-state-partial-compare-feedback.

The input for this crash is `\x05\x00\x00\x00WuRDTWICEohNO!@#`

