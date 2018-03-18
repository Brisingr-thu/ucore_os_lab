###Lab1实验报告
#####计45 王澎 2014011514
***
####练习1：理解通过make生成执行文件的过程
#####第1问
__操作系统镜像文件ucore.img是如何一步步地生成的？__  
为了研究生成ucore.img的过程需要阅读Makefile中具体构建ucore.img的代码。在Makefile中找到  

    UCOREIMG	:= $(call totarget,ucore.img)

    $(UCOREIMG): $(kernel) $(bootblock)
    $(V)dd if=/dev/zero of=$@ count=10000
    $(V)dd if=$(bootblock) of=$@ conv=notrunc
    $(V)dd if=$(kernel) of=$@ seek=1 conv=notrunc

    $(call create_target,ucore.img)  
上述代码块描述了ucore.img的建立过程。可以看到其中需要先加载bootblock（即bootloader）以及kernel。  
对于生成bootblock，在Makefile中找到

    bootfiles = $(call listf_cc,boot)
    $(foreach f,$(bootfiles),$(call cc_compile,$(f),$(CC),$(CFLAGS) -Os -nostdinc))

    bootblock = $(call totarget,bootblock)

    $(bootblock): $(call toobj,$(bootfiles)) | $(call totarget,sign)
    @echo + ld $@
    $(V)$(LD) $(LDFLAGS) -N -e start -Ttext 0x7C00 $^ -o $(call toobj,bootblock)
    @$(OBJDUMP) -S $(call objfile,bootblock) > $(call asmfile,bootblock)
    @$(OBJCOPY) -S -O binary $(call objfile,bootblock) $(call outfile,bootblock)
    @$(call totarget,sign) $(call outfile,bootblock) $(bootblock)

    $(call create_target,bootblock)
上述代码块描述的是bootblock的建立过程。这里的Makefile块事实上已经比较复杂。这时候可以通过

    make "V="
运行工程，并且输出make的信息。可以在其中看到，在连接源文件与目标文件生成生成bootblock之前，需要做的是

    + cc boot/bootasm.S //编译 bootasm.S
    + cc boot/bootmain.c //编译 bootmain.c
    + cc tools/sign.c //编译 sign.c
    + ld bin/bootblock//连接源文件与目标文件，生成bootblock程序
可见，在编译生成bootblock之前，我们需要做的是编译bootasm，bootmain以及sign。  
在编译bootasm的时候，实际编译器需要执行的指令是

    gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Os -nostdinc	-c boot/bootasm.S -o obj/boot/bootasm.o
在编译bootmain的时候，实际编译器需要执行的指令是

    gcc -Iboot/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc -fno-stack-protector -Ilibs/ -Os -nostdinc -c boot/bootmain.c -o obj/boot/bootmain.o
为了生成sign，在Makefile中其过程为

    $(call add_files_host,tools/sign.c,sign,sign)
    $(call create_target_host,sign,sign)
对应的在编译时候的命令为

    gcc -Itools/ -g -Wall -O2 -c tools/sign.c  	-o obj/sign/tools/sign.o
    gcc -g -Wall -O2 obj/sign/tools/sign.o -o bin/sign
上述这些工作都完成了之后，编译生成bootblock.o文件。对应的编译代码块为

    ld -m    elf_i386 -nostdlib -N -e start -Ttext 0x7C00 obj/boot/bootasm.o obj/boot/bootmain.o -o obj/bootblock.o
可以看到这里面指定了代码段开始的地址为0x7C00。  

下面考虑kernel的建立过程。  
在Makefile中，关于kernel建立的过程的代码块为：

    kernel = $(call totarget,kernel)

    $(kernel): tools/kernel.ld

    $(kernel): $(KOBJS)
	  @echo + ld $@
	  $(V)$(LD) $(LDFLAGS) -T tools/kernel.ld -o $@ $(KOBJS)
	  @$(OBJDUMP) -S $@ > $(call asmfile,kernel)
	  @$(OBJDUMP) -t $@ | $(SED) '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(call symfile,kernel)

    $(call create_target,kernel)
我们从make的编译信息中可以知道，为了生成kernel，我们需要得到：kernel.ld init.o readline.o stdio.o kdebug.o kmonitor.o panic.o clock.o console.o intr.o picirq.o trap.o trapentry.o vectors.o pmm.o  printfmt.o string.o。其编译的过程如下所示

    + cc kern/init/init.c       //编译 init.c
    + cc kern/libs/readline.c   //编译 readline.c
    + cc kern/libs/stdio.c      //编译 stdio.c
    + cc kern/debug/kdebug.c    //编译 kdebug.c
    + cc kern/debug/kmonitor.c  //编译 kmonitor
    + cc kern/debug/panic.c     //编译 panic.c
    + cc kern/driver/clock.c    //编译 clock.c
    + cc kern/driver/console.c  //编译 console.c
    + cc kern/driver/intr.c     //编译 intr.c
    + cc kern/driver/picirq.c   //编译 picirq.c
    + cc kern/trap/trap.c       //编译 trap.c
    + cc kern/trap/trapentry.S  //编译 trapentry.S
    + cc kern/trap/vectors.S    //编译 vector.S
    + cc kern/mm/pmm.c          //编译 pmm.c
    + cc libs/printfmt.c        //编译printgmt.c
    + cc libs/string.c          //编译 string.c
    + ld bin/kernel             //ld合并目标文件(object) 和 库文件(archive),生成kernel程序
在Makefile中控制这些生成文件的对应的代码块为

    KCFLAGS		+= $(addprefix -I,$(KINCLUDE))

    $(call add_files_cc,$(call listf_cc,$(KSRCDIR)),kernel,$(KCFLAGS))

    KOBJS	= $(call read_packet,kernel libs)
在实际的编译过程中，我们可以看到这些编译器实际上执行的编译命令为

    gcc -Ikern/init/ -fno-builtin -Wall -ggdb -m32 -gstabs -nostdinc  -fno-stack-protector -Ilibs/ -Ikern/debug/ -Ikern/driver/	-Ikern/trap/ -Ikern/mm/ -c kern/init/init.c -o obj/kern/init/init.o
上述为以init.c的编译为例的例子。对于其余的文件，我们可以看到其对应的编译过程与init.c非常类似。其编译的参数设置只是将上述编译init.c的参数中的init替换为了相应的文件名。  
下面我们需要关注kernel是如何将上述这些文件加载在一起的。需要注意的是makefile的几条指令中有@前缀的都不必需。实际编译器执行为指令为

    ld -m    elf_i386 -nostdlib -T tools/kernel.ld -o bin/kernel obj/kern/init/init.o obj/kern/libs/readline.o 	obj/kern/libs/stdio.o obj/kern/debug/kdebug.o obj/kern/debug/kmonitor.o obj/kern/debug/panic.o 	obj/kern/driver/clock.o obj/kern/driver/console.o obj/kern/driver/intr.o obj/kern/driver/picirq.o obj/kern/trap/trap.o obj/kern/trap/trapentry.o obj/kern/trap/vectors.o obj/kern/mm/pmm.o obj/libs/printfmt.o obj/libs/string.o
其中-T参数的作用是让连接器使用指定的脚本也就是kernel.ld  
至此我们就得到了kernel和bootblock。可以看到terminal中显示‘obj/bootblock.out’obj/bootblock.out的大小为472Bytes，并且build 512 bytes boot sector：‘bin/bootblock’ success!  
此时还需执行

    dd if=/dev/zero of=bin/ucore.img count=10000
用来生成一个有10000个块的文件，每个块默认512字节，用0填充。之后执行

    dd if=bin/bootblock of=bin/ucore.img conv=notrunc
用来将bootblock中的内容写到第一个块中。之后执行

    dd if=bin/kernel of=bin/ucore.img seek=1 conv=notrunc
用来将kernel中的内容写在从第二个块开始的内存之中。  
至此ucore.img全部生成完毕。
#####第2问
__一个被系统认为是符合规范的硬盘主引导扇区的特征是什么？__  
阅读代码tools/sign.c可以看到，首先

    char buf[512];
    memset(buf, 0, sizeof(buf));
其次从后面的输出的错误信息中可以看到

    size = fwrite(buf, 1, 512, ofp);
    if (size != 512) {
        fprintf(stderr, "write '%s' error, size is %d.\n", argv[2], size);
        return -1;
    }
所以我们知道一个磁盘主引导扇区有且只有512字节，并且

    buf[510] = 0x55;
    buf[511] = 0xAA;
即其最后两个字节（第510以及511）为0x55AA
***
####练习2: 使用qemu执行并调试lab1中的软件
#####第1问
__从CPU加电之后执行的第一条指令开始，单步跟踪BIOS的执行__  
为了对于BIOS进行单步跟踪，首先需要在Makefile中进行如下修改  

    debugBIOS: $(UCOREIMG)
		$(V)$(TERMINAL) -e "$(QEMU) -S -s -d in_asm -D $(BINDIR)/q.log -monitor stdio -hda $< -serial null"
		$(V)sleep 2
		$(V)$(TERMINAL) -e "gdb -q -x tools/gdbinit"
上述这一部分代码被加在Makefile的debug代码块之后。
之后对于tools目录下的gdbinit进行修改，在  

    target remote :1234
之前加上  

    set architecture i8086
然后执行  

    make debugBIOS
就可以看到进入了gdb并且可以进行单步跟踪  
我们利用gdb的单步调试可以得到  

    (gdb) si
    0x00100001    17    kern_init(void) {
    (gdb) si
    0x00100003    17    kern_init(void) {
    (gdb) si
    19      memset(edata, 0, end - edata);  
可以查看BIOS代码  

    (gdb) x /2i 0xffff0
       0xffff0:   ljmp    $0xf000,$0xe05b
       0xffff5:   xor     %dh,0x322f
    (gdb) x /10i  0xfe05b
       0xfe05b:   cmpl    $0x0,%cs:0x65a4
       0xfe062:   jne     0xfd2b9
       0xfe066:   xor     %ax,%ax
       0xfe068:   mov     %ax,%ss
       0xfe06a:   mov     $0x7000,%esp
       0xfe070:   mov     $0xf3c4f,%edx
       0xfe076:   jmp     0xfd12a
       0xfe079:   push    %ebp
       0xfe07b:   push    %edi
       0xfe07d:   push    %esi
同时反汇编结果可以在bin/q.log中查看。
#####第2问
__在初始化位置0x7c0设置实地址断点，测试断点正常__  
将tools目录下的gdbinit进行修改  

    file bin/kernel
	target remote :1234
	set architecture i8086
	b 0x7c00
	c  
	x /20i $pc
	set architecture i386
上述代码的含义为在bootloader的起始地址0x7c00处设置断点，并且显示当前eip处的汇编指令。  
接下来执行 make debugBIOS 可以看到输出结果：  

    Breakpoint 1, 0x00007c00 in ?? ()
    => 0x7c00:	cli    
       0x7c01:	cld    
       0x7c02:	xor    %ax,%ax
       0x7c04:	mov    %ax,%ds
       0x7c06:	mov    %ax,%es
       0x7c08:	mov    %ax,%ss
       0x7c0a:	in     $0x64,%al
       0x7c0c:	test   $0x2,%al
       0x7c0e:	jne    0x7c0a
       0x7c10:	mov    $0xd1,%al
       0x7c12:	out    %al,$0x64
       0x7c14:	in     $0x64,%al
       0x7c16:	test   $0x2,%al
       0x7c18:	jne    0x7c14
       0x7c1a:	mov    $0xdf,%al
       0x7c1c:	out    %al,$0x60
       0x7c1e:	lgdtw  0x7c6c
       0x7c23:	mov    %cr0,%eax
       0x7c26:  or     $0x1,%eax
       0x7c2a:  mov    %eax,%cr0
通过和boot/bootasm.S进行对比可以发现这些代码是一致的，从而断点正常。

#####第3问
__从0x7c00开始跟踪代码运行，将单步跟踪反汇编得到的代码与bootasm.S和bootblock.asm进行比较__  
由于在之前已经将反汇编代码保存在了 bin/q.log 中，我们直接打开q.log进行查看。在0x7c00的位置我们看到  

    ----------------
    IN:   
    0x00007c00:  cli    

    ----------------
    IN:
    0x00007c01:  cld    
    0x00007c02:  xor    %ax,%ax
    0x00007c04:  mov    %ax,%ds
    0x00007c06:  mov    %ax,%es
    0x00007c08:  mov    %ax,%ss

    ----------------
    IN:
    0x00007c0a:  in     $0x64,%al

    ----------------
    IN:
    0x00007c0c:  test   $0x2,%al
    0x00007c0e:  jne    0x7c0a

    ----------------
    IN:
    0x00007c10:  mov    $0xd1,%al
    0x00007c12:  out    %al,$0x64
    0x00007c14:  in     $0x64,%al
    0x00007c16:  test   $0x2,%al
    0x00007c18:  jne    0x7c14

    ----------------
    IN:
    0x00007c1a:  mov    $0xdf,%al
    0x00007c1c:  out    %al,$0x60
    0x00007c1e:  lgdtw  0x7c6c
    0x00007c23:  mov    %cr0,%eax
    0x00007c26:  or     $0x1,%eax
    0x00007c2a:  mov    %eax,%cr0

    ----------------
    IN:
    0x00007c2d:  ljmp   $0x8,$0x7c32

    ----------------
    IN:
    0x00007c32:  mov    $0x10,%ax
    0x00007c36:  mov    %eax,%ds

    ----------------
    IN:
    0x00007c38:  mov    %eax,%es

    ----------------
    IN:
    0x00007c3a:  mov    %eax,%fs
    0x00007c3c:  mov    %eax,%gs
    0x00007c3e:  mov    %eax,%ss

    ----------------
    IN:
    0x00007c40:  mov    $0x0,%ebp

    ----------------
    IN:
    0x00007c45:  mov    $0x7c00,%esp
    0x00007c4a:  call   0x7d0d
可以看到这些代码与bootasm.S中的代码相同

#####第4问
__自己找一个bootloader或内核中的代码位置，设置断点并进行测试__
对于kern_init(void)进行调试  
首先我们对于tools/gdbinit进行修改，将其修改为  

    file bin/kernel
    target remote :1234
    set architecture i8086
    break kern_init
    continue
运行指令 make debug 就可以启动gdb。并且此时gdb停在kern_init(void)的函数入口处。接下来可以查看之后会运行的机器指令的反汇编。运行 x /20i $pc 查看pc处之后的20条指令的反汇编，结果如下

    remote Thread 1 In： kern_init
    => 0x100000 <kern_init>:        push   %bp
       0x100001 <kern_init+1>:      mov    %sp,%bp
       0x100003 <kern_init+3>:      sub    $0x18,%sp
       0x100006 <kern_init+6>:      mov    $0xed20,%dx
       0x100009 <kern_init+9>:      adc    %al,(%bx,%si)
       0x10000b <kern_init+11>:     mov    $0xda18,%ax
       0x10000e <kern_init+14>:     adc    %al,(%bx,%si)
       0x100010 <kern_init+16>:     sub    %ax,%dx
       0x100012 <kern_init+18>:     mov    %dx,%ax
       0x100014 <kern_init+20>:     sub    %ax,0x24(%si)
       0x100017 <kern_init+23>:     or     %al,%bh
       0x100019 <kern_init+25>:     inc    %sp
       0x10001a <kern_init+26>:     and    $0x4,%al
       0x10001c <kern_init+28>:     add    %al,(%bx,%si)
       0x10001e <kern_init+30>:     add    %al,(%bx,%si)
       0x100020 <kern_init+32>:     movw   $0x1624,(%si)
       0x100024 <kern_init+36>:     ficoml (%bx,%si)
       0x100026 <kern_init+38>:     add     %ch,%al
       0x100028 <kern_init+40>:     push    %sp
       0x100029 <kern_init+41>:     xor     %al,(%bx,%si)
将上面得到的这些指令与kernel.asm中的kern_init(void)进行对比，可以发现其是一一对应的。       
***
####练习3
__分析bootloader进入保护模式的过程__  
初始CS寄存器为0，IP寄存器为0x7c00。在bootasm.S中我们可以看到，跳转到0x7c00地址后，首先将flag,DS,ES,SS置零：  

    .code16
        cli
        cld
        xorw %ax, %ax
        movw %ax, %ds
        movw %ax, %es
        movw %ax, %ss
之后就可以开启A20:  

    seta20.1:               # Wait for not busy(8042 input buffer empty).
        inb $0x64, %al      #
        testb $0x2, %al     #
        jnz seta20.1        #

        movb $0xd1, %al     # 0xd1 -> port 0x64
        outb %al, $0x64     # 0xd1 means: write data to 8042's P2 port

    seta20.2:               #
        inb $0x64, %al      # Wait for not busy(8042 input buffer empty).
        testb $0x2, %al     #
        jnz seta20.2        #

        movb $0xdf, %al     # 0xdf -> port 0x60
        outb %al, $0x60     # 0xdf = 11011111, means set P2's A20 bit(the 1 bit) to 1
开启A20的步骤：  
首先，等待8042 input buffer为空。这里通过读取in指令读取0x64地址处的8位数据，其中倒数第2低位表示input是否有数据。通过使用testb $0x2指令就可以判断这一位是否是1(test指令的效果类似于and的与操作，只不过test指令不存储值，故而经常使用test指令验某几位是否为1)。如果input置位，表示有数据，则向回跳转，继续等待input位置0；否则，此时input buffer为空。这时候继续向下执行。写0xd1到al寄存器中，之后使用out指令将0x21发送到0x64位置。这里0xd1的意义是将数据写到8042的P2端口。  
接下来，继续等待8042 input buffer为空。这里与上面类似。如果input buffer为空的话，则将0xdf的值存入al寄存器。之后再次利用out指令将al寄存器中的值写入0x60的地址。这里 0xdf = 1101111 其可以将A20的位置1。  
至于为什么需要开启A20Gate，这个问题是历史上从8086到80286的发展过程中出现的。在80286出现了24根地址总线之后，为了与只有20根地址总线的8086进行兼容，防止其访问100000H-10FFEFH之间的内存（这一部分内存需要第21至24根地址线），这时候就引入了A20Gate。当A20被禁止时：程序员给出100000H~10FFEFH间的地址，80286和8086/8088 的系统表现是一致的，即按照对1M求模的方式进行寻址，满足系统升级的兼容性问题；当A20被开启时：程序员给出的100000H~10FFEFH间的地址，80286是访问的真实地址，而8086/8088是始终是按照对1M求模的方式进行的（这里注意，是始终）。故而为了解决上述问题，IBM使用键盘控制器上剩余的一些输出线来管理第21根地址线（从0开始数是第20根），被称为A20Gate。在实模式到保护模式的切换过程中A20Gate起到了作用。  

接下来考虑加载全局中断表GDT。其是通过一条指令  

    lgdt gdtdesc
关于GDT有以下指令  

    gdt:
        SEG_NULLASM                                     # null seg
        SEG_ASM(STA_X|STA_R, 0x0, 0xffffffff)           # code seg for bootloader and kernel
        SEG_ASM(STA_W, 0x0, 0xffffffff)                 # data seg for bootloader and kernel

    gdtdesc:
        .word 0x17                                      # sizeof(gdt) - 1
        .long gdt                                       # address gdt

进入保护模式通过使能cr0寄存器的PE位  

    movl %cr0, %eax
    orl $CR0_PE_ON, %eax
    movl %eax, %cr0
之后跳转到32位的代码段地址  

    ljmp $PROT_MODE_CSEG, $protcseg
设置段寄存器DS，ES，FS，GS，SS，建立堆栈  

    .code32                                             # Assemble for 32-bit mode
    protcseg:
        # Set up the protected-mode data segment registers
        movw $PROT_MODE_DSEG, %ax                       # Our data segment selector
        movw %ax, %ds                                   # -> DS: Data Segment
        movw %ax, %es                                   # -> ES: Extra Segment
        movw %ax, %fs                                   # -> FS
        movw %ax, %gs                                   # -> GS
        movw %ax, %ss                                   # -> SS: Stack Segment

        # Set up the stack pointer and call into C. The stack region is from 0--start(0x7c00)
        movl $0x0, %ebp
        movl $start, %esp
完成模式切换，进入boot  

    call bootmain
***
####练习4
__分析bootloader加载ELF格式的OS的过程__  
从磁盘加载OS的主要代码集中在readsect,readseg和bootmain三个函数部分 readset负责读取单个扇区;readseg简单包装了readsect,可以从设备读取任意长度的内容;bootmain负责读取ELF。具体代码如下:  
readsect:  

    static void
		    readsect(void *dst, uint32_t secno) {
	        waitdisk();

	        outb(0x1F2, 1);                         // count=1 设置读取扇区的数目为1
	        outb(0x1F3, secno & 0xFF);
	        outb(0x1F4, (secno >> 8) & 0xFF);
	        outb(0x1F5, (secno >> 16) & 0xFF);
	        outb(0x1F6, ((secno >> 24) & 0xF) | 0xE0);
	            // 上面四条指令联合制定了扇区号,在这4个字节线联合构成的32位参数中
	            // 29-31位强制设为1
	            // 28位(=0)表示访问"Disk 0"
	            // 0-27位是28位的偏移量
	        outb(0x1F7, 0x20);                      // 0x20命令，读取扇区
          // wait for disk to be ready
	        waitdisk();

	        insl(0x1F0, dst, SECTSIZE / 4);         // 读取到dst位置，
	    }
可以看到该函数首先等待磁盘就绪，判断方式是读取IO地址寄存器0x1F7地址。就绪后，将读取扇区数，扇区号等信息写入0x1F2-0x1F7，再等待磁盘就绪，然后将数据读到内存里。  

readseg:  

    static void
    readseg(uintptr_t va, uint32_t count, uint32_t offset) {
    uintptr_t end_va = va + count;

    va -= offset % SECTSIZE;
    uint32_t secno = (offset / SECTSIZE) + 1;
    // 加1因为0扇区被引导占用
    // translate from bytes to sectors; kernel starts at sector 1

    for (; va < end_va; va += SECTSIZE, secno ++) {
      readsect((void *)va, secno);
    }
    }
可以看到它将offset转换成扇区号，并处理虚地址对齐，然后调用readsect读取磁盘扇区。readseg函数在readsect函数的基础上做了一个封装，从而可以从设备读取任意长度的内容。  

bootmain:  

    void
    bootmain(void) {
    // 读取ELF的头部
    readseg((uintptr_t)ELFHDR, SECTSIZE * 8, 0);

    // 判断ELF Header是否有效
    if (ELFHDR->e_magic != ELF_MAGIC) {
        goto bad;
    }

    struct proghdr *ph, *eph;

    // ELF头部有描述ELF文件应加载到内存什么位置的描述表，先将描述表的头地址存在ph
    ph = (struct proghdr *)((uintptr_t)ELFHDR + ELFHDR->e_phoff);
    eph = ph + ELFHDR->e_phnum;

    // 根据program header表，将磁盘中的可执行文件部分读到内存中
    for (; ph < eph; ph ++) {
        readseg(ph->p_va & 0xFFFFFF, ph->p_memsz, ph->p_offset);
    }
    // ELF文件0x1000位置后面的0xd1ec比特被载入内存0x00100000
    // ELF文件0xf000位置后面的0x1d20比特被载入内存0x0010e000

    // 读取完毕后，ucore已经被加载到了内存中，现在只需要跳转到操作系统入口执行，就可以运行起OS
    ((void (*)(void))(ELFHDR->e_entry & 0xFFFFFF))();

    bad:
    outw(0x8A00, 0x8A00);
    outw(0x8A00, 0x8E00);
    while (1);
    }
***
####练习5
__实现函数调用堆栈跟踪函数__  
在kdebug.c中实现print_stackframe如下：  

    void
    print_stackframe(void) {
     /* LAB1 2014011514 : STEP 1 */
     /* (1) call read_ebp() to get the value of ebp. the type is (uint32_t);
      * (2) call read_eip() to get the value of eip. the type is (uint32_t);
      * (3) from 0 .. STACKFRAME_DEPTH
      *    (3.1) printf value of ebp, eip
      *    (3.2) (uint32_t)calling arguments [0..4] = the contents in address (unit32_t)ebp +2 [0..4]
      *    (3.3) cprintf("\n");
      *    (3.4) call print_debuginfo(eip-1) to print the C calling function name and line number, etc.
      *    (3.5) popup a calling stackframe
      *           NOTICE: the calling funciton's return addr eip  = ss:[ebp+4]
      *                   the calling funciton's ebp = ss:[ebp]
      */
      uint32_t ebp = read_ebp();
      uint32_t eip = read_eip();
      int i,j;
      for (i = 0; ebp!= 0 && i < STACKFRAME_DEPTH; i++){
         cprintf("ebp:0x%08x eip:0x%08x ", ebp, eip);
         cprintf("args: ");
         for (j = 0; j < 4; j++)
            cprintf("0x%08x ", ((uint32_t *)ebp + 2)[j]);
         cprintf("\n");
         print_debuginfo(eip - 1);
         eip = *((uint32_t* )ebp+1);
         ebp = *((uint32_t* )ebp);
    }
    }

可以得到输出结果为：  

    Kernel executable memory footprint: 64KB
    ebp:0x00007b08 eip:0x001009a6 args: 0x00010094 0x00000000 0x00007b38 0x00100092 kern/debug/kdebug.c:306: print_stackframe+21
    ebp:0x00007b18 eip:0x00100c9b args: 0x00000000 0x00000000 0x00000000 0x00007b88 kern/debug/kmonitor.c:125: mon_backtrace+10
    ebp:0x00007b38 eip:0x00100092 args: 0x00000000 0x00007b60 0xffff0000 0x00007b64 kern/init/init.c:48: grade_backtrace2+33
    ebp:0x00007b58 eip:0x001000bb args: 0x00000000 0xffff0000 0x00007b84 0x00000029 kern/init/init.c:53: grade_backtrace1+38
    ebp:0x00007b78 eip:0x001000d9 args: 0x00000000 0x00100000 0xffff0000 0x0000001d kern/init/init.c:58: grade_backtrace0+23
    ebp:0x00007b98 eip:0x001000fe args: 0x001032fc 0x001032e0 0x0000130a 0x00000000 kern/init/init.c:63: grade_backtrace+34
    ebp:0x00007bc8 eip:0x00100055 args: 0x00000000 0x00000000 0x00000000 0x00010094 kern/init/init.c:28: kern_init+84
    ebp:0x00007bf8 eip:0x00007d68 args: 0xc031fcfa 0xc08ed88e 0x64e4d08e 0xfa7502a8 <unknown>: -- 0x00007d67 --
最后一行各个数值的含义是第一个使用堆栈的函数，即bootmain.c中的bootmain。意思是bootmain的ebp为0x7bf8。bootloader设置的堆栈从0x7c00开始，由于bootloader采用call指令进行压栈，堆栈最底部是最先被调用的函数bootmain。故而其对应ebp为0x7bf8。
***
####练习6
__完善中断初始化和处理__  
#####第1问
__中断描述符表（也可简称为保护模式下的中断向量表）中一个表项占多少字节？其中哪几位代表中断处理代码的入口？__
我们在kern/mm/mmu.h中可以看到：  

    /* Gate descriptors for interrupts and traps */
    struct gatedesc {
        unsigned gd_off_15_0 : 16;        // low 16 bits of offset in segment
        unsigned gd_ss : 16;            // segment selector
        unsigned gd_args : 5;            // # args, 0 for interrupt/trap gates
        unsigned gd_rsv1 : 3;            // reserved(should be zero I guess)
        unsigned gd_type : 4;            // type(STS_{TG,IG32,TG32})
        unsigned gd_s : 1;                // must be 0 (system)
        unsigned gd_dpl : 2;            // descriptor(meaning new) privilege level
        unsigned gd_p : 1;                // Present
        unsigned gd_off_31_16 : 16;        // high bits of offset in segment
    };
可以看到表项的详细定义。而表项的大小为 16+16+5+3+4+1+2+1+16 = 64，所以一个表项占8个字节。  
其中低16位（0...15）为偏移，高16位（48...63）为偏移，并且16至31位为段选择符（中断处理的例程的代码入口）  

#####第2问  
__请编程完善kern/trap/trap.c中对中断向量表进行初始化的函数idt_init。__  
首先查看mmu.h中的SETGATE宏：#define SETGATE(gate, istrap, sel, off, dpl)  
其中各项参数分别表示：  
gate：相应idt数组的内容  
istrap：系统段设置为1，中断门设置为0  
sel：段选择子  
off：为__vectors数组内容  
dpl：设置优先级   

    /* idt_init - initialize IDT to each of the entry points in kern/trap/vectors.S */
    void
    idt_init(void) {
         /* LAB1 2014011514 : STEP 2 */
         /* (1) Where are the entry addrs of each Interrupt Service Routine (ISR)?
          *     All ISR's entry addrs are stored in __vectors. where is uintptr_t __vectors[] ?
          *     __vectors[] is in kern/trap/vector.S which is produced by tools/vector.c
          *     (try "make" command in lab1, then you will find vector.S in kern/trap DIR)
          *     You can use  "extern uintptr_t __vectors[];" to define this extern variable which will be used later.
          * (2) Now you should setup the entries of ISR in Interrupt Description Table (IDT).
          *     Can you see idt[256] in this file? Yes, it's IDT! you can use SETGATE macro to setup each item of IDT
          * (3) After setup the contents of IDT, you will let CPU know where is the IDT by using 'lidt' instruction.
          *     You don't know the meaning of this instruction? just google it! and check the libs/x86.h to know more.
          *     Notice: the argument of lidt is idt_pd. try to find it!
          */
          //保存在vectors.S中的256个中断处理例程的入口地址数组
          extern uintptr_t __vectors[];
          int i;
          //在中断门描述符表中通过建立中断门描述符，其中存储了中断处理例程的代码段GD_KTEXT和偏移量__vectors[i]，特权级为DPL_KERNEL。这样通过查询idt[i]就可定位到中断服务例程的起始地址。
          for (i = 0; i < 256; i++) {
              SETGATE(idt[i], 0, GD_KTEXT, __vectors[i], DPL_KERNEL);
          }
          // set for switch from user to kernel
          SETGATE(idt[T_SWITCH_TOK], 0, GD_KTEXT, __vectors[T_SWITCH_TOK], DPL_USER);
          //建立好中断门描述符表后，通过指令lidt把中断门描述符表的起始地址装入IDTR寄存器中，从而完成中段描述符表的初始化工作。
          lidt(&idt_pd);
    }
代码如上所示。这一部分的任务是将中断信息添加到idt数组之中。其中需要对于中断号为T_SYSCALL以及T_SWITCH_TOK的中断进行特殊处理。最后设置IDTR寄存器，值为idt表的首地址。
#####第3问  
__请编程完善trap.c中的中断处理函数trap，在对时钟中断进行处理的部分填写trap函数__  
在trap_dispatch函数的case IRQ_OFFSET + IRQ_TIMER:中添加如下代码  

    ticks ++;
    if (ticks % TICK_NUM == 0) {
        print_ticks();
    }
    break;
实现过程：首先调用了kern/driver/clock.c中的全局变量ticks，ticks在kern/driver/clock.c已被初始化为0。然后每次增加100后调用一次print_ticks()
***
####Challenge实验  
见代码
