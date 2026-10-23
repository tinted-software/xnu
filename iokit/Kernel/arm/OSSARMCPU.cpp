/*
 * Minimal platform CPU driver for non-Apple-silicon arm64 boards (QEMU virt,
 * SUPERBIRD, IPAD41).
 *
 * On Apple silicon this job is done by the AppleARMPlatform/AppleARMCPU kexts
 * (and, in-tree, by iokit/Kernel/arm/AppleARMSMP.cpp when USE_APPLEARMSMP is
 * defined): they instantiate an IOCPUInterruptController, size it to the
 * machine's CPU count, register the machine's processors with the scheduler and
 * register the controller with the platform expert.
 *
 * Our boards define neither USE_APPLEARMSMP nor ship those kexts, so none of
 * that happened.  Two consequences broke the boot:
 *
 *   1. IOCPUInterruptController::initCPUInterruptController() is the only
 *      caller of ml_set_max_cpus() in the whole system, so ml_wait_max_cpus()
 *      (reached from kperf_init_early(), right after PE_lockdown_iokit() in
 *      kernel_bootstrap_thread) slept forever and the boot never reached
 *      bsd_init().
 *   2. Nothing called ml_processor_register(), so no processor was ever marked
 *      booted and sched_cpu_init_completed() panicked with
 *      "processor_boot() missing for cpu 0".
 *
 * The work is split in two phases because IOCPUInitialize() runs extremely
 * early - from iokit_post_constructor_init(), before IORegistryEntry, IOService
 * and the platform expert exist:
 *
 *   Phase 1 (synchronous): allocate the controller and size it.  This is the
 *           call that reaches ml_set_max_cpus(), so it must happen before
 *           anything can block in ml_wait_max_cpus().
 *   Phase 2 (deferred):    once a platform expert has been matched, attach and
 *           register the controller, register each CPU, and announce that CPU
 *           initialization is complete.
 */

extern "C" {
#include <pexpert/pexpert.h>
}

#include <machine/machine_routines.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOCPU.h>
#include <kern/thread.h>

#if !USE_APPLEARMSMP

/*
 * Concrete IOCPU for these boards.
 *
 * PE_cpu_machine_init()/PE_cpu_signal() and friends in the !USE_APPLEARMSMP
 * branch of IOCPU.cpp treat the cpu_id_t handed to ml_processor_register() as
 * an IOCPU object pointer (they OSDynamicCast it), so a real IOCPU instance is
 * required - passing a bare integer index panics with
 * "PE_cpu_machine_init: invalid target CPU".
 *
 * Secondary cores are never released from reset on these ports (MAX_CPUS is 1
 * and there is no PSCI CPU_ON bring-up yet), so startCPU/haltCPU/quiesceCPU
 * have nothing to do.
 */
class OSSARMCPU : public IOCPU
{
	OSDeclareDefaultStructors(OSSARMCPU);

public:
	/* setCPUNumber() is protected in IOCPU; expose it for the initializer. */
	void                   configureCPUNumber(UInt32 cpuNumber);

	virtual void           initCPU(bool boot) APPLE_KEXT_OVERRIDE;
	virtual void           quiesceCPU(void) APPLE_KEXT_OVERRIDE;
	virtual kern_return_t  startCPU(vm_offset_t start_paddr,
	    vm_offset_t arg_paddr) APPLE_KEXT_OVERRIDE;
	virtual void           haltCPU(void) APPLE_KEXT_OVERRIDE;
	virtual const OSSymbol *getCPUName(void) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(OSSARMCPU, IOCPU);

void
OSSARMCPU::configureCPUNumber(UInt32 cpuNumber)
{
	setCPUNumber(cpuNumber);
}

void
OSSARMCPU::initCPU(bool /*boot*/)
{
	setCPUState(kIOCPUStateRunning);
}

void
OSSARMCPU::quiesceCPU(void)
{
}

kern_return_t
OSSARMCPU::startCPU(vm_offset_t /*start_paddr*/, vm_offset_t /*arg_paddr*/)
{
	/* Secondary CPU bring-up is not implemented on these boards. */
	return KERN_FAILURE;
}

void
OSSARMCPU::haltCPU(void)
{
}

const OSSymbol *
OSSARMCPU::getCPUName(void)
{
	char name[16];

	snprintf(name, sizeof(name), "CPU%u", (unsigned int)getCPUNumber());
	return OSSymbol::withCString(name);
}

static IOCPUInterruptController *gOSSCPUInterruptController;

/* Bounded wait for the platform expert: 100ms * 600 = up to 60s. */
#define OSS_PLATFORM_WAIT_MS     100
#define OSS_PLATFORM_WAIT_TRIES  600

static void
oss_arm_cpu_publish_thread(void */*arg*/, wait_result_t /*wr*/)
{
	IOService *platform = NULL;

	for (int i = 0; i < OSS_PLATFORM_WAIT_TRIES; i++) {
		platform = IOService::getPlatform();
		if (platform != NULL) {
			break;
		}
		IOSleep(OSS_PLATFORM_WAIT_MS);
	}

	if (platform == NULL) {
		IOLog("OSSARMCPU: no platform expert appeared; "
		    "CPU interrupt controller left unregistered\n");
		return;
	}

	/*
	 * registerCPUInterruptController() calls registerService() and then
	 * getPlatform()->registerInterruptController(), so the controller needs a
	 * provider in the service plane first - otherwise IOService complains
	 * ("not registry member at registerService()").
	 */
	if (!gOSSCPUInterruptController->attach(platform)) {
		IOLog("OSSARMCPU: failed to attach CPU interrupt controller\n");
		return;
	}
	gOSSCPUInterruptController->registerCPUInterruptController();

	/*
	 * Register every CPU the ARM topology parser found.  On !USE_APPLEARMSMP
	 * ml_processor_register() calls processor_boot() itself, which is what
	 * marks the processor as booted - sched_cpu_init_completed() panics with
	 * "processor_boot() missing for cpu N" otherwise.
	 *
	 * There is no IOPMGR on these boards, so the idle/powergate hooks are left
	 * NULL; ml_processor_register() simply stores them.
	 */
	const ml_topology_info_t *topology = ml_get_topology_info();
	for (unsigned int cpu = 0; topology != NULL && cpu < topology->num_cpus; cpu++) {
		const ml_topology_cpu *cpu_info = &topology->cpus[cpu];
		ml_processor_info_t this_processor_info;
		processor_t processor = NULL;
		ipi_handler_t ipi_handler = NULL;
		perfmon_interrupt_handler_func pmi_handler = NULL;

		OSSARMCPU *iocpu = new OSSARMCPU;
		if (iocpu == NULL || !iocpu->init()) {
			panic("OSSARMCPU: failed to create IOCPU for cpu %u",
			    cpu_info->cpu_id);
		}
		iocpu->configureCPUNumber(cpu_info->cpu_id);

		memset(&this_processor_info, 0, sizeof(this_processor_info));
		this_processor_info.cpu_id = (cpu_id_t)iocpu;
		this_processor_info.phys_id = cpu_info->phys_id;
		this_processor_info.log_id = cpu_info->cpu_id;
		this_processor_info.cluster_id = cpu_info->cluster_id;
		this_processor_info.cluster_type = cpu_info->cluster_type;
		this_processor_info.l2_cache_size = cpu_info->l2_cache_size;
		this_processor_info.l2_cache_id = cpu_info->l2_cache_id;
		this_processor_info.l3_cache_size = cpu_info->l3_cache_size;
		this_processor_info.l3_cache_id = cpu_info->l3_cache_id;

		if (ml_processor_register(&this_processor_info, &processor,
		    &ipi_handler, &pmi_handler) == KERN_FAILURE) {
			panic("OSSARMCPU: ml_processor_register failed for cpu %u",
			    cpu_info->cpu_id);
		}
	}

	ml_cpu_init_completed();
	IOService::publishResource(gIOAllCPUInitializedKey, kOSBooleanTrue);
}

/*
 * Called from IOCPUInitialize() (iokit/Kernel/IOCPU.cpp, !USE_APPLEARMSMP
 * branch).
 */
void
oss_arm_cpu_initialize(void)
{
	const ml_topology_info_t *topology = ml_get_topology_info();
	unsigned int num_cpus = (topology != NULL && topology->num_cpus > 0) ?
	    topology->num_cpus : 1;

	gOSSCPUInterruptController = new IOCPUInterruptController;
	if (gOSSCPUInterruptController == NULL) {
		panic("OSSARMCPU: failed to allocate IOCPUInterruptController");
	}

	/*
	 * Performs the super::init() for us and, crucially, calls
	 * ml_set_max_cpus() - which is what wakes any thread blocked in
	 * ml_wait_max_cpus().
	 */
	if (gOSSCPUInterruptController->initCPUInterruptController((int)num_cpus)
	    != kIOReturnSuccess) {
		panic("OSSARMCPU: initCPUInterruptController(%u) failed", num_cpus);
	}

	thread_t thread;
	if (kernel_thread_start(&oss_arm_cpu_publish_thread, NULL, &thread) != KERN_SUCCESS) {
		panic("OSSARMCPU: failed to start cpu publish thread");
	}
	thread_set_thread_name(thread, "oss_arm_cpu_publish");
	thread_deallocate(thread);
}

#endif /* !USE_APPLEARMSMP */
