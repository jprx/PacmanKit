/*
 * PacmanKit
 * Kernel support for the PACMAN DEF CON 30 talk.
 * Joseph Ravichandran
 */

#include <libkern/OSDebug.h>
#include <kern/task.h>
#include <os/log.h>
#include <sys/proc.h>
#include <sys/vm.h>
#include "pacmandc.hpp"

#define LOG_PREFIX "[PacmanKit]"

OSDefineMetaClassAndStructors(PacmanKit, IOService)
OSDefineMetaClassAndStructors(PacmanUser, IOUserClient)

#define LIMIT __static_data[0]
__attribute__((aligned((0x4000)))) static uint64_t __static_data[0x4000] = {0x10};

// Dispatch table for the PacmanKit IOUserClient (PacmanUser)
const IOExternalMethodDispatch PacmanUser::Methods[kPacmanClientNumMethods] = {
    {KernelBaseLeak, 0, 0, 1, 0,},
    {ReadMemoryUnsafe, 1, 0, 1, 0,},
    {WriteMemory, 2, 0, 0, 0,},
    {KernelVirt2Phys, 1, 0, 1, 0,},
    {UserVirt2Phys, 1, 0, 1, 0,},
    {IOUserClientLeak, 0, 0, 1, 0,},
    {GimmeMemory, 0, 0, 1, 0},
    {FreeMemory, 0, 0, 0, 0},
    {TellMeRegs, 0, 0, 2, 0},
    {ReadMemoryForTiming, 2, 0, 1, 0},
    {ExecMemoryForTiming, 2, 0, 1, 0},
    {LeakMethod, 0, 0, 3, 0},
    {ReadForSpectre, 2, 0, 0, 0},
    {ExecForSpectre, 2, 0, 0, 0},
    {CallServiceRoutine, 6, 0, 1, 0},
    {ForgeSignData, 2, 0, 1, 0},
    {ForgeAuthData, 2, 0, 1, 0},
    {ForgeSignInst, 2, 0, 1, 0},
    {ForgeAuthInst, 2, 0, 1, 0},
    {LeakCurProc, 0, 0, 1, 0},
};

// Loads `addr`, returns the number of cycles required to access it.
uint64_t time_access(uint64_t addr) {
    uint64_t val_out;
    uint64_t t1, t2;
    asm volatile(
        "dsb sy\n"
        "isb\n"
        "mrs %[t1], S3_2_c15_c0_0\n"
        "isb\n"
        "ldr %[val_out], [%[addr]]\n"
        "isb\n"
        "mrs %[t2], S3_2_c15_c0_0\n"
        "isb\n"
        "dsb sy\n"
        : [val_out]"=r"(val_out), [t1]"=r"(t1), [t2]"=r"(t2)
        : [addr]"r"(addr)
    );
    return t2 - t1;
}

// Executes `addr`, returns the number of cycles required to access it.
uint64_t time_execute(uint64_t addr) {
    uint64_t t1, t2;
    asm volatile(
        "dsb sy\n"
        "isb\n"
        "mrs %[t1], S3_2_c15_c0_0\n"
        "isb\n"
        "blr %[addr]\n"
        "isb\n"
        "mrs %[t2], S3_2_c15_c0_0\n"
        "isb\n"
        "dsb sy\n"
        : [t1]"=r"(t1), [t2]"=r"(t2)
        : [addr]"r"(addr)
        : "lr"
    );
    return t2 - t1;
}

// Returns the kernel base address (will need to be updated whenever the kernelcache changes)
IOReturn KernelBaseLeak(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    IOReturn ret = kIOReturnSuccess;

    uint64_t os_rel_ptr = (uint64_t)&os_release | PAC_BITMASK;
    uint64_t kernel_base = os_rel_ptr - OFFSET_OS_RELEASE;
    args->scalarOutput[0] = kernel_base;

    return ret;
}

// Read a quadword of kernel memory through an IOMemoryDescriptor to ensure it is safe to do so
// This API is deprecated and unavailable via the IOUserClient
IOReturn ReadMemorySafe(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    IOReturn ret = kIOReturnSuccess;
    IOByteCount bytes_read;
    bool prepare_called = false;
    mach_vm_address_t targetAddr = (mach_vm_address_t)args->scalarInput[0];
    mach_vm_size_t bytes_to_read = 8;
    uint64_t read_val = 0;

    args->scalarOutput[0] = 0;

    IOMemoryDescriptor *descriptor = IOMemoryDescriptor::withAddressRange(targetAddr, bytes_to_read, kIODirectionOut, kernel_task);

    if (NULL == descriptor) {
        ret = kIOReturnError;
        goto out;
    }

    {
        ret = descriptor->prepare();
        if (ret != kIOReturnSuccess) goto out;
        prepare_called = true;
    }

    bytes_read = descriptor->readBytes(0, &read_val, sizeof(read_val));
    if (bytes_read != sizeof(read_val)) {
        ret = kIOReturnError;
    }
    args->scalarOutput[0] = read_val;

out:
    if (NULL != descriptor) {
        if (prepare_called) descriptor->complete();
        descriptor->release();
        descriptor = NULL;
    }

    return ret;
}

// Read a quadword of kernel memory without checking the pointer at all
// This is what happens when the PacmanRead externalMethod is called
IOReturn ReadMemoryUnsafe(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    uint64_t val_out, addr;
    addr = args->scalarInput[0] | PAC_BITMASK;
    asm volatile(
        "ldr %[val_out], [%[addr]]\n"
        : [val_out]"=r"(val_out)
        : [addr]"r"(addr)
    );
    args->scalarOutput[0] = val_out;
    return kIOReturnSuccess;
}

// Write a quadword of kernel memory
IOReturn WriteMemory(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    IOReturn ret = kIOReturnSuccess;
    IOByteCount bytes_written;
    bool prepare_called = false;
    mach_vm_address_t targetAddr = (mach_vm_address_t)args->scalarInput[0];
    mach_vm_size_t bytes_to_write = 8;
    uint64_t write_val = args->scalarInput[1];

    IOMemoryDescriptor *descriptor = IOMemoryDescriptor::withAddressRange(targetAddr, bytes_to_write, kIODirectionIn, kernel_task);

    if (NULL == descriptor) {
        ret = kIOReturnError;
        goto out;
    }

    {
        ret = descriptor->prepare();
        if (ret != kIOReturnSuccess) goto out;
        prepare_called = true;
    }

    bytes_written = descriptor->writeBytes(0, &write_val, sizeof(write_val));
    if (bytes_written != sizeof(write_val)) {
        ret = kIOReturnError;
    }

out:
    if (NULL != descriptor) {
        if (prepare_called) descriptor->complete();
        descriptor->release();
        descriptor = NULL;
    }

    return ret;
}

// Translate a kernel virtual address to a physical address
IOReturn KernelVirt2Phys(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    IOReturn ret = kIOReturnSuccess;
    bool prepare_called = false;
    mach_vm_address_t targetAddr = (mach_vm_address_t)args->scalarInput[0];
    mach_vm_size_t bytes_to_read = 8;

    args->scalarOutput[0] = 0;

    IOMemoryDescriptor *descriptor = IOMemoryDescriptor::withAddressRange(targetAddr, bytes_to_read, kIODirectionOut, kernel_task);

    if (NULL == descriptor) {
        ret = kIOReturnError;
        goto out;
    }

    {
        ret = descriptor->prepare();
        if (ret != kIOReturnSuccess) goto out;
        prepare_called = true;
    }

    args->scalarOutput[0] = descriptor->getPhysicalAddress();;

out:
    if (NULL != descriptor) {
        if (prepare_called) descriptor->complete();
        descriptor->release();
        descriptor = NULL;
    }

    return ret;
}

// Translate a user virtual address to a physical address
IOReturn UserVirt2Phys(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    IOReturn ret = kIOReturnSuccess;
    bool prepare_called = false;
    mach_vm_address_t targetAddr = (mach_vm_address_t)args->scalarInput[0];
    mach_vm_size_t bytes_to_read = 8;

    args->scalarOutput[0] = 0;

    // Or could just use current_task() instead of storing the task port in the IOUserClient
    IOMemoryDescriptor *descriptor = IOMemoryDescriptor::withAddressRange(targetAddr, bytes_to_read, kIODirectionOut, ((PacmanUser *)target)->task);

    if (NULL == descriptor) {
        ret = kIOReturnError;
        goto out;
    }

    {
        ret = descriptor->prepare();
        if (ret != kIOReturnSuccess) goto out;
        prepare_called = true;
    }

    args->scalarOutput[0] = descriptor->getPhysicalAddress();;

out:
    if (NULL != descriptor) {
        if (prepare_called) {
            descriptor->complete();
        }
        descriptor->release();
        descriptor = NULL;
    }

    return ret;
}

// Leak the address of this IOUserClient
IOReturn IOUserClientLeak(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    args->scalarOutput[0] = ((uint64_t)target) | PAC_BITMASK;
    return kIOReturnSuccess;
}

// Return a pointer to a chunk of kernel memory
// This is SUPER not thread safe
#define M1_PAGE_SZ ((0x4000ULL))
#define KERN_MMAP_SIZE ((0xC000 * (M1_PAGE_SZ)))
static uint8_t *kern_mmap_region = NULL;
IOReturn GimmeMemory(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    if (NULL == kern_mmap_region) {
        kern_mmap_region = (uint8_t *)IOMallocAligned(KERN_MMAP_SIZE, M1_PAGE_SZ);

        if (NULL == kern_mmap_region) {
            return kIOReturnError;
        }

        memset(kern_mmap_region, 0x41, KERN_MMAP_SIZE);
    }
    args->scalarOutput[0] = (uint64_t)kern_mmap_region;
    return kIOReturnSuccess;
}

// Free memory allocated by GimmeMemory
// This is SUPER not thread-safe
IOReturn FreeMemory(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    if (NULL != kern_mmap_region) {
        IOFreeAligned(kern_mmap_region, KERN_MMAP_SIZE);
        kern_mmap_region = NULL;
    }
    return kIOReturnSuccess;
}

// Return the value of some EL1-only registers
IOReturn TellMeRegs(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    args->scalarOutput[0] = SREG_READ(SREG_PMCR0);
    args->scalarOutput[1] = SREG_READ("CNTKCTL_EL1");
    return kIOReturnSuccess;
}

// Do an unchecked read when args[1] is true (nothing when it is false)
// This should be used for simulating a speculative LDR
// Returns the number of CYCLES to access the address!
IOReturn ReadMemoryForTiming(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    if (args->scalarInput[1]) {
        args->scalarOutput[0] = time_access((args->scalarInput[0] | PAC_BITMASK));
//        args->scalarOutput[0] = *((uint64_t *)(args->scalarInput[0] | PAC_BITMASK));
    }
    return kIOReturnSuccess;
}

// Do an unchecked exec when args[1] is true (nothing when it is false)
// This should be used for simulating a speculative BLR
// Returns the number of CYCLES to exec the address!
IOReturn ExecMemoryForTiming(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    if (args->scalarInput[1]) {
        args->scalarOutput[0] = time_execute((args->scalarInput[0] | PAC_BITMASK));
    }
    return kIOReturnSuccess;
}

// Leaks the address of retpoline region and LIMIT
IOReturn LeakMethod(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    args->scalarOutput[0] = ((uint64_t)(&retpoline)) | PAC_BITMASK;
    args->scalarOutput[1] = ((uint64_t)(&LIMIT)) | PAC_BITMASK;
    args->scalarOutput[2] = 0x4343434343434ULL; // Don't use this!
    return kIOReturnSuccess;
}

// Read args[0] if args[1] is less than the LIMIT global varaible, do nothing otherwise
IOReturn ReadForSpectre(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    uint64_t val_out, addr, flush_me;
//    flush_me = ((uint64_t)(&LIMIT)) | PAC_BITMASK;
//    asm volatile(
//        "dc civac, %[flush_me]\n"
//        :
//        : [flush_me]"r"(flush_me)
//    );
    if (args->scalarInput[1] < LIMIT) {
        addr = args->scalarInput[0];
        asm volatile(
            "ldr %[val_out], [%[addr]]\n"
            : [val_out]"=r"(val_out)
            : [addr]"r"(addr)
        );
    }
    return kIOReturnSuccess;
}

// Exec args[0] if args[1] is less than the LIMIT global varaible, do nothing otherwise
IOReturn ExecForSpectre(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    uint64_t addr;
    if (args->scalarInput[1] < LIMIT) {
        addr = args->scalarInput[0];
        asm volatile(
            "blr %[addr]\n"
            :
            : [addr]"r"(addr)
            : "lr"
        );
    }
    return kIOReturnSuccess;
}

// Defer to the PacmanKitService class
IOReturn CallServiceRoutine(OSObject *target, void *reference, IOExternalMethodArguments *args) __attribute__((aligned(0x80))) {
    // uint64_t outval;
//    uint64_t flush_me = ((uint64_t)(&LIMIT)) | PAC_BITMASK;
//    asm volatile(
//        "dc civac, %[flush_me]\n"
//        :
//        : [flush_me]"r"(flush_me)
//    );
    if (args->scalarInput[0] < LIMIT) {
//        return ((PacmanUser *)target)->helper.externalMethod();

        // The no-blraa way:
         asm volatile(
                     "ldr x16, [%[helper]]\n"
                     "mov x17, %[helper]\n"
                     "movk x17, #0xd986, lsl #48\n"
                     "autda x16, x17\n"
                     "ldr x8, [x16]\n"
                     "mov    x9, x16\n"
                     "mov    x17, x9\n"
                     "movk   x17, #0xa7d5, lsl #48\n"
                     "autia x8, x17\n"
                     "blr x8"
                      :
                      : [helper]"r"(&((PacmanUser *)target)->helper)
                      : "x8", "x9", "x16", "x17", "lr"
         );

        // The exact C++ way:
//       asm volatile(
//                   "ldr x16, [%[helper]]\n"
//                   "mov x17, %[helper]\n"
//                   "movk x17, #0xd986, lsl #48\n"
//                   "autda x16, x17\n"
//                   "ldr x8, [x16]\n"
//                   "mov    x9, x16\n"
//                   "mov    x17, x9\n"
//                   "movk   x17, #0xa7d5, lsl #48\n"
//                   "blraa  x8, x17\n"
//                    :
//                    : [helper]"r"(&((PacmanUser *)target)->helper)
//                    : "x8", "x9", "x16", "x17", "lr"
//       );
//        IOLog(LOG_PREFIX "outval is 0x%llX\n", outval);
    }
    return kIOReturnSuccess;
}

// pacda with arbitrary salt
IOReturn ForgeSignData(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    args->scalarOutput[0] = pac_sign_data(args->scalarInput[0], args->scalarInput[1]);
    return kIOReturnSuccess;
}

// autda with arbitrary salt
IOReturn ForgeAuthData(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    args->scalarOutput[0] = pac_auth_data(args->scalarInput[0], args->scalarInput[1]);
    return kIOReturnSuccess;
}

// pacia with arbitrary salt
IOReturn ForgeSignInst(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    args->scalarOutput[0] = pac_sign_inst(args->scalarInput[0], args->scalarInput[1]);
    return kIOReturnSuccess;
}

// autia with arbitrary salt
IOReturn ForgeAuthInst(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    args->scalarOutput[0] = pac_auth_inst(args->scalarInput[0], args->scalarInput[1]);
    return kIOReturnSuccess;
}

// Reveal the current proc pointer
IOReturn LeakCurProc(OSObject *target, void *reference, IOExternalMethodArguments *args) {
    args->scalarOutput[0] = (uint64_t)current_proc() | PAC_BITMASK;
    return kIOReturnSuccess;
}

IOReturn PacmanKitService::externalMethod() {
//    IOLog(LOG_PREFIX "PacmanKitService call (0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX)", arg1, arg2, arg3, arg4, arg5, arg6);
    return kIOReturnSuccess;
}

bool PacmanKit::start(IOService *provider) {
    bool ret;

    ret = IOService::start(provider);
    if (!ret) {
        IOService::stop(provider);
        return false;
    }

    registerService();
    return ret;
}

bool PacmanUser::initWithTask(task_t owningTask, void * securityToken, UInt32 type) {
    if (!owningTask) return false;
    if (!IOUserClient::initWithTask(owningTask, securityToken, type)) return false;
    this->task = owningTask;
    return true;
}

IOReturn PacmanUser::clientClose() {
    terminate();
    return kIOReturnSuccess;
}

IOReturn PacmanUser::externalMethod(uint32_t selector,
                                    IOExternalMethodArguments * args,
                                    IOExternalMethodDispatch * dispatch,
                                    OSObject * target,
                                    void * reference) {
    if (selector >= kPacmanClientNumMethods) {
        return kIOReturnUnsupported;
    }
    return IOUserClient::externalMethod(selector, args, (IOExternalMethodDispatch *)&Methods[selector], this, NULL);
}
