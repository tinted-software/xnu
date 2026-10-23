/*
 * Minimal Itanium C++ ABI runtime support the kernel is missing outside
 * a full libc++abi. The kernel never "exits" in the libc sense, so
 * __cxa_atexit has nothing meaningful to register destructors against;
 * -fno-c++-static-destructors (see meson.build) already suppresses
 * namespace-scope static destructor registration, but function-local
 * static initialization guards can still emit a call to this symbol.
 * Reporting success without recording anything is correct here: nothing
 * will ever run the recorded destructor anyway.
 */

int
__cxa_atexit(void (*func)(void *), void *arg, void *dso_handle)
{
	(void)func; (void)arg; (void)dso_handle;
	return 0;
}

