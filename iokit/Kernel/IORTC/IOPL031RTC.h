/*
 * IOPL031RTC: a genuine IOService driver for the ARM PL031 RTC exposed by
 * QEMU's `virt` machine (see hw/arm/virt.c: VIRT_RTC @ 0x0901_0000).
 *
 * Unlike the earlier STARTUP()-hack pattern used for com.apple.kec.corecrypto
 * in this tree, this driver is instantiated through the *real* IOKit
 * built-in-personality matching path: its IOKitPersonalities entry (embedded
 * in the `__BUILTIN,__info` Mach-O section -- see IOPL031RTCBuiltinInfo.c)
 * is picked up by KLDBootstrap::readBuiltinPersonalities() at boot, pushed
 * to the IOCatalogue, and matched by IOKit's normal driver-matching engine
 * against the always-present "IOResources" provider singleton -- the same
 * mechanism real macOS uses for hardware-independent built-in drivers. No
 * code manually constructs or starts this object; IOService::start() is
 * invoked by the matching thread exactly like any dynamically loaded kext.
 *
 * start() maps the PL031 registers and publishes the "IORTC" resource, which
 * is what unblocks IOKitInitializeTime()'s `waitForService(IORTC)` in
 * iokit/Kernel/IOStartIOKit.cpp -- previously that call always ran to its
 * full 30-second timeout because nothing ever published that resource.
 *
 * IOKitInitializeTime waits on the IORTC resource this driver publishes.
 */

#ifndef _IOPL031RTC_H
#define _IOPL031RTC_H

#include <IOKit/IOService.h>
#include <IOKit/IOMemoryDescriptor.h>

class IOPL031RTC : public IOService
{
	OSDeclareDefaultStructors(IOPL031RTC);

public:
	virtual bool start(IOService * provider) APPLE_KEXT_OVERRIDE;
	virtual void stop(IOService * provider) APPLE_KEXT_OVERRIDE;

private:
	OSPtr<IOMemoryDescriptor> _regDesc;
	OSPtr<IOMemoryMap> _regMap;
};

#endif /* _IOPL031RTC_H */
