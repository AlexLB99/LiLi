#! /bin/bash

#/* These steps should to be run after you called `relocator` on vimlinux which
# * should generate tmp.elf 
#*/

ls tmp.elf 1>/dev/null 2>/dev/null
if [[ $? -ne 0 ]]
then
	echo "error: no tmp.elf. Run relocator to generate."
	exit 0
fi

#/* Add (in-place) [.modinfo] and [.gnu.linkonce.this_module] sections from binary files (included, extracted from
# * the included .ko file). Also remove existing [.rela] section (might create problems during module loading if kept). 
# * Finally, rename some sections so they don't cause issues during module loading 
#*/
 echo "[+] Adding/removing section"
 aarch64-linux-gnu-objcopy \
 	--add-section .modinfo=sections/modinfo.bin \
	--set-section-flags .modinfo=contents,alloc,load \
	tmp.elf tmp.elf
 aarch64-linux-gnu-objcopy \
 	--add-section .gnu.linkonce.this_module=sections/gnu.linkonce.this_module.bin \
	--set-section-flags .gnu.linkonce.this_module=contents,alloc,load \
	tmp.elf tmp.elf
 aarch64-linux-gnu-objcopy --remove-section=.rela tmp.elf tmp.elf
 aarch64-linux-gnu-objcopy --rename-section __ksymtab=dummy1 tmp.elf tmp.elf
 aarch64-linux-gnu-objcopy --rename-section __ksymtab_gpl=dummy2 tmp.elf tmp.elf
 aarch64-linux-gnu-objcopy --rename-section __ksymtab_strings=dummy3 tmp.elf tmp.elf
 aarch64-linux-gnu-objcopy --rename-section __param=dummy4 tmp.elf tmp.elf

#/* Now we need to choose the initializtion function for our module. The pointer to this function should
# * live in [.gnu.linkonce.this_module] section at offset 344.
# *
# * This is done by adding relocation for the init function. 
# * Below, `255493` is the offset (in decimal) of <meson_uvm_init> function from the section start
# * (use relocator to get that offset). `4294967553` is relocation <info> parameter. The left 4 bytes is the
# * new symbol's index in the symbol table (you need to run readelf -sW to get that number). The right 4 bytes
# * is the type and can be left unchanged:  4294967553 = 0x00000001 00000101 <- don't change this
# *                                                           ^
# *                                                           |
# *                                                       change this
#*/
 echo "[+] Adding init module relocations (using default meson_uvm_init)"
 ../bim2lkm/new_symbol tmp.elf my_init 255492 44 LOCAL FUNC DEFAULT .init.text tmp1.elf
 ../bim2lkm/new_rela_sec tmp1.elf .gnu.linkonce.this_module tmp2.elf
 #recover the index of the symbol we just added, then calculate info parameter
 init_sym_ndx=$(readelf -s tmp2.elf --wide | awk -v sym_name="my_init" '{if ($8 == sym_name) print substr($1, 1, length($1)-1);}' | tail -n 1) #get the index of the symbol we just added
 relSymNumHex=$(printf '%x\n' $init_sym_ndx)
 relType="00000101"
 relInfoHex="$relSymNumHex$relType"
 relInfoDec=$(echo $((16#$relInfoHex)))
 ../bim2lkm/new_reloc tmp2.elf 344 $relInfoDec 0 .rela.gnu.linkonce.this_module tmp3.elf
 ../bim2lkm/new_reloc tmp3.elf 760 $relInfoDec 0 .rela.gnu.linkonce.this_module tmp3.elf
 cp tmp3.elf tmp.elf
 rm tmp1.elf tmp2.elf tmp3.elf


#/* Add protos section, remove debugging sections */
 echo "[+] Adding/removing more section"
 aarch64-linux-gnu-objcopy \
 	--add-section protos=sections/protos.bin \
	--set-section-flags protos=contents,alloc,load \
	tmp.elf tmp.elf
 aarch64-linux-gnu-objcopy \
 	--remove-section=.debug* \
 	--remove-section=.data..percpu \
 	--remove-section=.got.plt \
 	--remove-section=.mmuoff.data.write \
 	--remove-section=.mmuoff.data.read \
 	--remove-section=.altinst* \
	tmp.elf tmp.elf

#/* This is step is to get read of all symbols except for those that are need for relocations:
# * i.e. <meson_uvm_init>, and the ones restored by `relocator` (-K is short for --keep-symbol)
#*/
 echo "[+] Stripping unnecessary symbols"
 aarch64-linux-gnu-objcopy \
	--strip-all \
	-K printk \
	-K __platform_driver_register \
	-K my_init \
	tmp.elf tmp.elf \

 cp tmp.elf vmlinux.ko
 echo "[+] rm tmp.elf"
 rm tmp.elf

echo "All done. Now load vmlinux.ko to the evasion kernel"

#/* Now load `vmlinux.ko` to the evasion kernel */

