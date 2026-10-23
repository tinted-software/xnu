// SPDX-License-Identifier: GPL-2.0
/*
 * com.apple.security.sandbox: the sandbox MAC policy, as a kext in the
 * kernelcache (tools/buck/kernelcache.py).
 *
 * Unmodified userspace calls __mac_syscall("Sandbox", call, arg) through
 * libsystem_sandbox. This kext registers the policy named "Sandbox" and
 * answers the calls it implements. Every other call fails closed with ENOTSUP.
 *
 * STAND-IN for Apple's kext of the same name: only call 0x43
 * (sandbox_get_container_expected) is implemented. Apple's kext is prelinked
 * in the IPSW kernelcache with no symbol table, so its call table is not yet
 * reversed. Flagged in the final report.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>
#include <mach/kmod.h>
#include <security/mac_policy.h>

#define SANDBOX_POLICY_NAME "Sandbox"

/*
 * The kext's Info.plist. kernelcache.py reads it from here to describe the
 * kext in the collection's prelink plist; a security extension is loaded by
 * the kernel itself during startup, before launchd runs.
 */
__attribute__((section("__TEXT,__info"), used))
static const char sbx_info_plist[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\">\n"
    "<dict>\n"
    "\t<key>AppleSecurityExtension</key>\n\t<true/>\n"
    "\t<key>CFBundleDevelopmentRegion</key>\n\t<string>English</string>\n"
    "\t<key>CFBundleExecutable</key>\n\t<string>Sandbox</string>\n"
    "\t<key>CFBundleIdentifier</key>\n\t<string>com.apple.security.sandbox</string>\n"
    "\t<key>CFBundleInfoDictionaryVersion</key>\n\t<string>6.0</string>\n"
    "\t<key>CFBundleName</key>\n\t<string>Seatbelt sandbox policy</string>\n"
    "\t<key>CFBundlePackageType</key>\n\t<string>KEXT</string>\n"
    "\t<key>CFBundleShortVersionString</key>\n\t<string>300.0</string>\n"
    "\t<key>CFBundleSignature</key>\n\t<string>????</string>\n"
    "\t<key>CFBundleVersion</key>\n\t<string>300.0</string>\n"
    "\t<key>OSBundleCompatibleVersion</key>\n\t<string>1.0.0d1</string>\n"
    "\t<key>OSBundleRequired</key>\n\t<string>Root</string>\n"
    "\t<key>OSBundleLibraries</key>\n\t<dict>\n"
    "\t\t<key>com.apple.kpi.bsd</key>\n\t\t<string>12.0.0</string>\n"
    "\t\t<key>com.apple.kpi.libkern</key>\n\t\t<string>10.0.0</string>\n"
    "\t\t<key>com.apple.kpi.private</key>\n\t\t<string>10.0.0</string>\n"
    "\t</dict>\n"
    "</dict>\n"
    "</plist>\n";


/* Sandbox call numbers observed in libsystem_sandbox.dylib (__mac_syscall). */
#define SBX_CALL_GET_CONTAINER_EXPECTED 0x43

struct sbx_container_expected_args {
	user_addr_t out0;
	user_addr_t out1;
};

static int
sbx_get_container_expected(user_addr_t arg)
{
	struct sbx_container_expected_args ca;
	uint64_t app_container = 0;
	uint64_t ext_container = 0;
	int error;

	error = copyin(arg, &ca, sizeof(ca));
	if (error) {
		return error;
	}
	/* launchd (pid 1) is a system-session process: not containerized. */
	error = copyout(&app_container, ca.out0, sizeof(app_container));
	if (error == 0) {
		error = copyout(&ext_container, ca.out1, sizeof(ext_container));
	}
	return error;
}

static int
sbx_policy_syscall(struct proc *p __unused, int call, user_addr_t arg)
{
	switch (call) {
	case SBX_CALL_GET_CONTAINER_EXPECTED:
		return sbx_get_container_expected(arg);
	default:
		return ENOTSUP;
	}
}

static struct mac_policy_ops sbx_policy_ops = {
	.mpo_policy_syscall = sbx_policy_syscall,
};

static const char *sbx_labelnames[] = { "sbx" };

static struct mac_policy_conf sbx_policy_conf = {
	.mpc_name = SANDBOX_POLICY_NAME,
	.mpc_fullname = "Seatbelt sandbox policy (stand-in)",
	.mpc_field_off = NULL,
	.mpc_labelnames = sbx_labelnames,
	.mpc_labelname_count = 1,
	.mpc_ops = &sbx_policy_ops,
	.mpc_loadtime_flags = 0,
	.mpc_runtime_flags = 0,
};

static mac_policy_handle_t sbx_policy_handle;

static kern_return_t
sandbox_kext_start(kmod_info_t *ki __unused, void *d __unused)
{
	int error = mac_policy_register(&sbx_policy_conf, &sbx_policy_handle, NULL);
	if (error != 0) {
		printf("com.apple.kec.sandbox: mac_policy_register failed: %d\n", error);
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

static kern_return_t
sandbox_kext_stop(kmod_info_t *ki __unused, void *d __unused)
{
	/* Policies are not unloadable while processes may still call them. */
	return KERN_FAILURE;
}

KMOD_EXPLICIT_DECL(com.apple.kec.sandbox, "300.0", sandbox_kext_start, sandbox_kext_stop)
