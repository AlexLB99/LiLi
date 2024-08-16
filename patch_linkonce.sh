#!/bin/bash

#This script patches .rela.gnu.linkonce.this_module with relocations to our module's init and exit function symbols

if [ $# -lt 2 ]
  then
    echo "First argument should be path to ELF file (e.g., vmlinux)"
    echo "All subsequent arguments should be names of source files for the driver"
    echo "Ex: main.sh test/vmlinux file1.c file2.c"
    exit
fi
input_file=$1
shift; #we don't need that arg anymore

#copy blob-injected.ko to blob-injected-final.ko and work on that (blob-injected.ko will be unchanged)
cp blob-injected.ko blob-injected-final.ko

#Compile a dummy .ko file to see the offsets for a module's init and exit funcs in linkonce section
#If this doesn't work, the script exits
make clean_mod
make dummy_mod
if [ ! -f nulldrv.ko ]; then
	echo "ERROR (patch_linkonce.sh): The compilation of a dummy driver failed, make sure it can compile. Exiting without patching linkonce."
	exit
fi

linkonce_relocs=$(readelf -r nulldrv.ko --wide | grep ".rela.gnu.linkonce.this_module" -A 3 | tail -n 2) #gets the rela entries for init and exit funcs
init_offset_hex=$(echo "$linkonce_relocs" | head -n 1 | awk '{print $1}') #gets the offset of the init func relocation in linkonce section
init_offset_dec=$(echo $((16#$init_offset_hex))) #converts the offset to from hex to dec
exit_offset_hex=$(echo "$linkonce_relocs" | tail -n 1 | awk '{print $1}') #gets the offset of the exit func relocation in linkonce section
exit_offset_dec=$(echo $((16#$exit_offset_hex)))


#Get the init and exit function names
initcalls=()
exitcalls=()

for src_file in "$@"
do
	src_file_sym="$(readelf -s $input_file --wide | awk -v file_name="$src_file" '{if ($8 == file_name) print $0}')"
	symtab_sec=$(readelf -s $input_file --wide | grep "$src_file_sym" -A 10000 | awk -vN=2 'n<2;/FILE/{++n}' | sed 1,1d | sed '$d') #the part of the vmlinux symbol relevant to our module
	
	initcall_symbols=$(echo "$symtab_sec" | grep "__initcall_" | awk '{print $8}')
	if [[ ! -z "$initcall_symbols" ]]; then
		while IFS= read -r initcall_symbol; do #add all the module init funcs (not all __init) to initcalls list
			if [[ $initcall_symbol == *rootfs ]]; then #if initcall_rootfs, need to change suffix to use the same system as the others
				initcall_symbol="${initcall_symbol::-6}5t" #change "rootfs" suffix to "5t", placing this between fs_initcall_sync and device_initcall
				echo $initcall_symbol
			fi
			initcallPriority=$(echo ${initcall_symbol:11} | sed -E 's/.*([0-9])/\1/g') #take the last part of initcall symbol name, which is the initcall priority
			sortable_initcall="$initcallPriority$initcall_symbol" #put the initcall priority level at the beginning of the sym name, to make sorting easier
			initcalls+=($sortable_initcall)
		done <<< "$initcall_symbols"
	fi
	
	#we don't really need to do this for exit functions, since they're not really relevant in fuzzing
	#in the end, we'll just take to the last exit function the script finds and arbitrarily call that our module's exit func
	exitcall_symbol=$(echo "$symtab_sec" | grep "__exitcall_" | awk '{print $8}') 
	if [[ ! -z "$exitcall_symbol" ]]; then
		exitFuncName=$(echo ${exitcall_symbol:11} | sed 's|\(.*\)[0-9].*|\1|') #strip off the "__exitcall_" prefix and the number suffix to get the function name
		exitcalls+=($exitFuncName)
	fi
done


#Take the initFuncNames and order them
IFS=$'\n' sorted_initcalls=($(sort <<<"${initcalls[*]}")); unset IFS #this sorts the array of symbol names based on initcall order
#now that we have the right order, store the init func sym indexes, instead of using the name (since two funcs can have the same name)
#how it works: get the reloc that is at the offset of initcall sym -- that reloc's addend will be the offset of the init func sym
for i in "${!sorted_initcalls[@]}" 
do
	curr_initcall="__$(echo ${sorted_initcalls[$i]} | awk -F__ '{print $2}')"
	if [[ "${curr_initcall: -2}" == "5t" ]]; then #get the offset of the init function (special case for rootfs_initcall)
		initcall_ofs=$(readelf -s blob-injected-final.ko --wide | grep -w "${curr_initcall:0:-2}rootfs" | awk '{print $2}')
	else
		initcall_ofs=$(readelf -s blob-injected-final.ko --wide | grep -w "$curr_initcall" | awk '{print $2}')
	fi
	init_func_ofs=$(readelf -r blob-injected-final.ko --wide | awk -v initcall_ofs="$initcall_ofs" '{if ($1 ~ initcall_ofs) print $7;}')
	init_func_ofs_padded=$(printf "%016X\n" "0x$init_func_ofs")
	init_sym_ndx=$(readelf -s blob-injected-final.ko --wide | awk -v init_func_ofs_padded="${init_func_ofs_padded,,}" '{if ($2 == init_func_ofs_padded) print $1;}')
	sorted_initcalls[$i]=$(echo ${init_sym_ndx::-1})
done

#Ask for the user to specify the init function order if combining multiple modules
#TODO: input symbol table index instead of names, since different init funcs can have the same name
while true; do
    read -p "Do you wish to manually specify the init function order? [y/n] " yn
    case $yn in
        [Yy]* ) 
        	read -p $'Enter the symtab indexes of your init funcs in the order you want them called, ex: 31 18...\n' init_funcs
        	unset sorted_initcalls
        	for init_func in $init_funcs; do
        		sorted_initcalls+=($init_func)
        	done
        	break
        	;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done

printf "[%s]\n" "${sorted_initcalls[@]}"

#have a .c file ready, add code (calls to empty function) using this script and make (use android gcc)
cp custom_mod_init_base.c custom_mod_init.c
for i in "${!sorted_initcalls[@]}" #for each initcall, we add a call to empty_func1() in our c file
do
   echo -e "$(sed $'4 i \\\tempty_func1();' custom_mod_init.c)" > custom_mod_init.c
done
make custom_mod_init

#extract the init function code and put it at the beginning of blob's .text (since it's unused kernel code)
init_sym=$(readelf -s custom_mod_init.o --wide | grep "my_init_func")
text_sec_offset="0x$(readelf -S custom_mod_init.o --wide | grep -w ".text " | awk -F] '{print $2}' | awk '{print $4}')"
init_sym_val="0x$(echo $init_sym | awk '{print $2}')"
init_sym_size=$(echo $init_sym | awk '{print $3}')
init_sym_offset=$(printf "%X\n" $(($text_sec_offset + $init_sym_val))) #offset of symbol in file = offset of text sec + offset of symbol from beginning of text sec
init_sym_offset=$(echo $((16#$init_sym_offset))) #convert the result from hex to dec
dd skip=$init_sym_offset count=$init_sym_size if=custom_mod_init.o of=init_func bs=1 #extract the function's binary
mod_text_sec_offset=$(readelf -S blob-injected-final.ko --wide | grep -w ".text " | awk -F] '{print $2}' | awk '{print $4}')
mod_text_sec_offset=$(echo $((16#$mod_text_sec_offset)))
dd count=$init_sym_size seek=$mod_text_sec_offset if=init_func of=blob-injected-final.ko bs=1 conv=notrunc

#add the relocations
init_sym_end_address=$((init_sym_size-4))
init_sym_size_hex=$(printf '%x\n' $init_sym_end_address)
custom_init_hexdump=$(aarch64-linux-gnu-objdump -Dj .text blob-injected-final.ko | grep -m 1 -w "$init_sym_size_hex:" -B $((init_sym_end_address/4)))
bl_lines=$(echo "$custom_init_hexdump" | grep "bl")
i=0
while IFS= read -r line; do #for each bl statement we find, add a relocation to relevant init function in the order defined above
	relOffsetHex=$(echo $line | cut -d ":" -f1)
	relOffsetDec=$(echo $((16#$relOffsetHex)))
	blob_init_sym_index=$(echo "${sorted_initcalls[$i]}")
	blob_init_sym_index=$(printf '%x\n' $blob_init_sym_index) #convert the symbol's index from hex to dec
	relInfoHex=$blob_init_sym_index"0000011b"
	relInfoDec=$(echo $((16#$relInfoHex)))
	
	./new_reloc blob-injected-final.ko $relOffsetDec $relInfoDec 0 ".rela.text" blob-injected-final.ko
	
	i=$i+1
done <<< "$bl_lines"

#add a symbol for our new function
./new_symbol blob-injected-final.ko "custom_init_func" 0 $init_sym_size "LOCAL" "FUNC" "DEFAULT" ".text" blob-injected-final.ko


#add a relocation in .rela.gnu.linkonce.this_module for init function
initSymPos=$(readelf -s blob-injected-final.ko --wide | grep -w "custom_init_func" | awk '{print $1}')
initSymPosHex=$(printf '%x\n' ${initSymPos::-1})
relInfoHex=$initSymPosHex"00000101"
relInfoDec=$(echo $((16#$relInfoHex)))
./new_reloc blob-injected-final.ko $init_offset_dec $relInfoDec 0 ".rela.gnu.linkonce.this_module" blob-injected-final.ko

#add a relocation in .rela.gnu.linkonce.this_module for .exit.text -- since we don't care what it is , we'll just make it custom_init_func
./new_reloc blob-injected-final.ko $exit_offset_dec $relInfoDec 0 ".rela.gnu.linkonce.this_module" blob-injected-final.ko


#cleaning up, optional
rm init_func
make clean_mod
