CXX = \e[1;34m[CXX]\e[0m
RM = \e[1;34m[RM]\e[0m
PROGRAM = relocator
INCLUDE=ELFIO

all: main.cpp
	@echo "$(CXX) $< -> $(PROGRAM)"
	@g++ -I$(INCLUDE) $< -lcapstone -o $(PROGRAM)
	
inject: 
	aarch64-linux-gnu-gcc -mcmodel=large -mpc-relative-literal-loads -fno-PIC -fno-short-enums -c inject2.c

obj-m := nulldrv.o
dummy_mod:
	make -C ../ M=$(PWD) ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- modules
	
custom_mod_init:
	aarch64-linux-gnu-gcc -fno-short-enums -c custom_mod_init.c

clean_mod:
	rm -f nulldrv.ko *.o *.mod.c *.order *.symvers

clean:
	@echo "$(RM) $(PROGRAM)"
	@rm -rf $(PROGRAM) *.o *.mod.c *.order *.symvers

distclean:
	@echo "$(RM) $(PROGRAM) Makefile *.ko *.o *.mod.c *.order *.symvers" 
	@rm -rf $(PROGRAM) Makefile *.ko *.o *.mod.c *.order *.symvers

