/*
 * PacmanKit
 * Kernel support for the PACMAN DEF CON 30 talk.
 */

#ifndef PACMAN_DC_H
#define PACMAN_DC_H

#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include "kernel.development.symbols.h"

// The important registers for PMC
// See osfmk/arm64/kpc.c
#define SREG_PMCR0  "S3_1_c15_c0_0"
#define SREG_PMCR1  "S3_1_c15_c1_0"
#define SREG_PMC0 "S3_2_c15_c0_0"
#define SREG_PMC1 "S3_2_c15_c1_0"

/*
 * SREG_WRITE
 * See osfmk/arm64/kpc.c
 * Write into an MSR using an instruction barrier afterwords
 * MSR[SR] <- V
 */
#define SREG_WRITE(SR, V) \
    __asm__ volatile("msr " SR ", %0 \r\n isb \r\n" : : "r"((uint64_t)V))

/*
 * SREG_READ
 * See osfmk/arm64/kpc.c
 * Read from an MSR without any instruction barriers
 * Returns MSR[SR]
 */
#define SREG_READ(SR)                                       \
({                                                          \
    uint64_t VAL = 0;                                       \
    __asm__ volatile("mrs %0, " SR " \r\n" : "=r"(VAL));    \
    VAL;                                                    \
})

// OR with this to remove a PAC for kernel pointers
#define PAC_BITMASK ((0xFFFF800000000000ULL))

/*
 * pac_sign_inst
 * Performs PACIA (sign instruction pointer with A key) on addr using
 * salt given by salt.
 *
 * Returns the signed pointer
 */
__attribute__((always_inline)) static inline uint64_t pac_sign_inst(uint64_t addr, uint64_t salt) {
    uint64_t result = addr;
    asm volatile(
         "pacia %[result], %[salt] \n\r" \
         : [result]"+r"(result)
         : [salt]"r"(salt)
         :
    );
    return result;
}

/*
 * pac_auth_inst
 * Performs AUTIA (authenticate instruction pointer with A key) on addr using
 * salt given by salt.
 *
 * Returns the signed pointer
 */
__attribute__((always_inline)) static inline uint64_t pac_auth_inst(uint64_t addr, uint64_t salt) {
    uint64_t result = addr;
    asm volatile(
        "autia %[result], %[salt] \n\r"
        : [result]"+r"(result)
        : [salt]"r"(salt)
        :
    );
    return result;
}

/*
 * pac_sign_data
 * Performs PACDA (sign data pointer with A key) on addr using
 * salt given by salt.
 *
 * Returns the signed pointer
 */
__attribute__((always_inline)) static inline uint64_t pac_sign_data(uint64_t addr, uint64_t salt) {
    uint64_t result = addr;
    asm volatile(
         "pacda %[result], %[salt] \n\r" \
         : [result]"+r"(result)
         : [salt]"r"(salt)
         :
    );
    return result;
}

/*
 * pac_auth_data
 * Performs AUTDA (authenticate data pointer with A key) on addr using
 * salt given by salt.
 *
 * Returns the signed pointer
 */
__attribute__((always_inline)) static inline uint64_t pac_auth_data(uint64_t addr, uint64_t salt) {
    uint64_t result = addr;
    asm volatile(
        "autda %[result], %[salt] \n\r"
        : [result]"+r"(result)
        : [salt]"r"(salt)
        :
    );
    return result;
}

enum PacmanKitOption {
    PacmanKernelBase,
    PacmanRead,
    PacmanWrite,
    PacmanKernelVirt2Phys,
    PacmanUserVirt2Phys,
    PacmanIOUserClientLeak,
    PacmanGimmeMemory,
    PacmanFreeMemory,
    PacmanTellMeRegs,
    PacmanReadForTiming,
    PacmanExecForTiming,
    PacmanLeakMethod,
    PacmanReadForSpectre,
    PacmanExecForSpectre,
    PacmanCallServiceRoutine,
    PacmanSignData,
    PacmanAuthData,
    PacmanSignInst,
    PacmanAuthInst,
    PacmanLeakProc,
};

typedef uint64_t u64;

/* Client Service class. This is used as a server for extra PacmanKit method calls (`PacmanCallServiceRoutine`). */
class PacmanKitService {
public:
    /* Handle PacmanCallServiceRoutine externalMethod calls for PacmanUser. */
    /* This is the target of our PACMAN attack. */
    virtual IOReturn externalMethod();
};

const size_t kPacmanClientNumMethods = 20;

/*
 * The IOClass for PACMAN. This is the driver's main class.
 *
 * We use 'IOResources' for the IOProviderClass (in Info.plist) as that is a generic IOKit service.
 * We set 'IOResourceMatch' to 'IOKit' to specify that this driver should be loaded whenever IOKit is ready.
 */
class PacmanKit : public IOService {
    OSDeclareDefaultStructors(PacmanKit)
    virtual bool start(IOService *provider) override;
};

/*
 * The IOUserClientClass for PACMAN. This is the IOUserClient that interacts with userspace.
 */
class PacmanUser : public IOUserClient {
    OSDeclareDefaultStructors(PacmanUser)

public:
    task_t task;
    const static IOExternalMethodDispatch Methods[];
    PacmanKitService helper;

    bool initWithTask(
        task_t owningTask, void * securityToken, UInt32 type
    ) override;

    IOReturn externalMethod(
                            uint32_t selector,
                            IOExternalMethodArguments * args,
                            IOExternalMethodDispatch * dispatch,
                            OSObject * target,
                            void * reference
    ) override;

    IOReturn clientClose() override;
};

/* PacmanUser API */
IOReturn KernelBaseLeak(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ReadMemorySafe(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ReadMemoryUnsafe(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn WriteMemory(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn KernelVirt2Phys(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn UserVirt2Phys(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn IOUserClientLeak(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn GimmeMemory(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn FreeMemory(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn TellMeRegs(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ReadMemoryForTiming(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ExecMemoryForTiming(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn LeakMethod(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ReadForSpectre(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ExecForSpectre(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn CallServiceRoutine(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ForgeSignData(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ForgeAuthData(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ForgeSignInst(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn ForgeAuthInst(OSObject *target, void *reference, IOExternalMethodArguments *args);
IOReturn LeakCurProc(OSObject *target, void *reference, IOExternalMethodArguments *args);

/* Helper routines */
static void do_nothing(void);
static void win(void);

extern "C" void retpoline(void);

extern "C" void win_c(void);

#endif // PACMAN_DC_H
