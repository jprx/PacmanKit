
#ifndef kernel_development_symbols_h
#define kernel_development_symbols_h

// What offset from the mach-o header is
// os_release in your kernelcache?

// You can find this out by making a core dump and
// checking within lldb.

// This is what it is for me on MacOS 12.4 T8101, but it might be different for you!

#define OFFSET_OS_RELEASE ((0x9B6874))

#error "Before installing PacmanKit, verify that the OFFSET_OS_RELEASE variable is correct for your environment!"

#endif /* kernel_development_symbols_h */
