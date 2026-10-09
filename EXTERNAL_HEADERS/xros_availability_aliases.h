/*
 * xros availability aliases.
 *
 * Apple renamed xrOS to visionOS; the storage platform name remained
 * `visionos`. AvailabilityVersions' DSL records `cmd_aliases=xros` for that
 * platform, but the released generator does not emit the corresponding
 * __API_*_PLATFORM_xros macros. xnu headers (osfmk/mach/exclaves.h) still
 * spell availability with xros(...), so provide the aliases here.
 *
 * Force-included (-include) so it applies wherever the availability macro
 * family is used; it only defines names the generator leaves undefined.
 */
#ifndef __XROS_AVAILABILITY_ALIASES__
#define __XROS_AVAILABILITY_ALIASES__

#ifndef __API_AVAILABLE_PLATFORM_xros
#define __API_AVAILABLE_PLATFORM_xros(x) visionos,introduced=x
#endif
#ifndef __API_DEPRECATED_PLATFORM_xros
#define __API_DEPRECATED_PLATFORM_xros(x, y) visionos,introduced=x,deprecated=y
#endif
#ifndef __API_OBSOLETED_PLATFORM_xros
#define __API_OBSOLETED_PLATFORM_xros(x, y, z) visionos,introduced=x,deprecated=y,obsoleted=z
#endif
#ifndef __API_UNAVAILABLE_PLATFORM_xros
#define __API_UNAVAILABLE_PLATFORM_xros visionos,unavailable
#endif

/*
 * exclavekit is an internal platform the released AvailabilityVersions DSL
 * does not describe at all, yet shipped headers (dyld's
 * DYLD_EXCLAVEKIT_UNAVAILABLE) spell availability with it. Record the
 * attribute against driverkit -- another non-macOS platform -- so the
 * annotation is preserved and inert for this macOS-target build.
 */
#ifndef __API_AVAILABLE_PLATFORM_exclavekit
#define __API_AVAILABLE_PLATFORM_exclavekit(x) driverkit,introduced=x
#endif
#ifndef __API_DEPRECATED_PLATFORM_exclavekit
#define __API_DEPRECATED_PLATFORM_exclavekit(x, y) driverkit,introduced=x,deprecated=y
#endif
#ifndef __API_OBSOLETED_PLATFORM_exclavekit
#define __API_OBSOLETED_PLATFORM_exclavekit(x, y, z) driverkit,introduced=x,deprecated=y,obsoleted=z
#endif
#ifndef __API_UNAVAILABLE_PLATFORM_exclavekit
#define __API_UNAVAILABLE_PLATFORM_exclavekit driverkit,unavailable
#endif

/*
 * dyld's shipped headers reference DYLD_EXCLAVEKIT_UNAVAILABLE but never
 * define it (the definition lives in Apple-internal SDK headers).
 */
#ifndef DYLD_EXCLAVEKIT_UNAVAILABLE
#define DYLD_EXCLAVEKIT_UNAVAILABLE __API_UNAVAILABLE(exclavekit)
#endif

#endif /* __XROS_AVAILABILITY_ALIASES__ */
