"""Rules that pin a target to one platform, whoever depends on it.

`default_target_platform` only applies to a target built from the command line;
a dependency inherits its dependent's platform. The QEMU runner is a host tool
that needs the kernelcache (aarch64-darwin) and the loader (aarch64-none), so
each is wrapped in a rule with an *incoming* transition to its own platform
(https://buck2.build/docs/concepts/transitions/#using-incoming-transitions).
Depending on the wrapper, from any platform, yields the wrapped target's outputs
as built for that platform.
"""

def _to_darwin(platform, refs):
    return refs.darwin[PlatformInfo]

def _to_none(platform, refs):
    return refs.none[PlatformInfo]

_darwin = transition(
    impl = _to_darwin,
    refs = {"darwin": "//platforms:aarch64-darwin"},
)

_none = transition(
    impl = _to_none,
    refs = {"none": "//platforms:aarch64-none"},
)

def _forward(ctx):
    # The wrapped target's outputs, unchanged.
    return [ctx.attrs.actual[DefaultInfo]]

_ATTRS = {"actual": attrs.dep()}

# `actual` as configured for the freestanding kernel (aarch64-apple-darwin).
darwin_artifact = rule(impl = _forward, attrs = _ATTRS, cfg = _darwin)

# `actual` as configured for bare metal (aarch64-unknown-none).
bare_metal_artifact = rule(impl = _forward, attrs = _ATTRS, cfg = _none)
