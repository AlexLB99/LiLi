__attribute__((section(".modinfo")))
char modinfo_strings[] = 
"name=" NAME;

__attribute__((section(".gnu.linkonce.this_module")))
struct module {
    char __pad0[0x18];
    char name[sizeof(NAME)];
    char __pad1[0x340 - 0x18 - sizeof(NAME)];
} __attribute__((packed))
__this_module = {
    .name = NAME,
};
