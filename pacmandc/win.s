
// This may be a bit of a misnomer, this is a giant trampoline made of retpolines
// but this is not the same thing as the Spectre v1 mitigation in Linux of the same name
.global _retpoline

.extern _win_c

//pub const RET_INST : u32 = 0xd65f03c0;
//pub const NOP_INST : u32 = 0xd503201f;

.align 21
_retpoline:
    .fill 0x1000,4,0xD503201F
    b _win_c
