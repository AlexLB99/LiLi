# LiLi

This tool is used to enable the fuzzing of Android kernel drivers directly from binrary Android kernel images. It works by wrapping the kernel image (vmlinux) in a loadable kernel module, and patching it so that it can run in a stock Linux kernel. 

Note that the [Evasion framework](https://github.com/ivanpustogarov/evasion-framework) (which this tool also depends on) allows to run Android LKMs in stock Linux kernels, but the key difference is that these LKMs need to be compiled as stand-alone modules from source code. With LiLi, you just need the Android kernel binary, you do not need the source code, or the ability to compile it.

For precise instructions, please refer to the instructions in main.sh, and for more context, see [our paper](https://alexlb99.github.io/files/2024-ISC.pdf).
