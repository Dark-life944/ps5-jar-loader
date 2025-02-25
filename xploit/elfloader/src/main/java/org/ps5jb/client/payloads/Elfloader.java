package org.ps5jb.client.payloads;

import org.ps5jb.client.utils.init.SdkInit;
import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.kernel.KernelAccessorIPv6;
import org.ps5jb.sdk.core.kernel.KernelOffsets;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.lib.LibKernel;

import java.io.*;


public class Elfloader implements Runnable {
    private static final int OFF_EHDR_TYPE  = 0x10;
    private static final int OFF_EHDR_ENTRY = 0x18;
    private static final int OFF_EHDR_PHOFF = 0x20;
    private static final int OFF_EHDR_SHOFF = 0x28;
    private static final int OFF_EHDR_PHNUM = 0x38;
    private static final int OFF_EHDR_SHNUM = 0x3c;

    private static final int OFF_PHDR_TYPE   = 0x00;
    private static final int OFF_PHDR_FLAGS  = 0x04;
    private static final int OFF_PHDR_OFFSET = 0x08;
    private static final int OFF_PHDR_VADDR  = 0x10;
    private static final int OFF_PHDR_FILESZ = 0x20;
    private static final int OFF_PHDR_MEMSZ  = 0x28;

    private static final int OFF_SHDR_TYPE   = 0x04;
    private static final int OFF_SHDR_OFFSET = 0x18;
    private static final int OFF_SHDR_SIZE   = 0x20;

    private static final int OFF_RELA_OFFSET = 0x00;
    private static final int OFF_RELA_INFO   = 0x08;
    private static final int OFF_RELA_ADDEND = 0x10;

    private static final int SIZE_PHDR = 0x38;
    private static final int SIZE_EHDR = 0x40;
    private static final int SIZE_SHDR = 0x40;
    private static final int SIZE_RELA = 0x18;

    private static final int ET_EXEC = 2;
    private static final int ET_DYN  = 3;

    private static final int PT_LOAD = 0x01;

    private static final int SHT_RELA = 4;

    private static final int R_X86_64_RELATIVE = 8;

    private static final int PF_X = 0x1;
    private static final int PF_W = 0x2;
    private static final int PF_R = 0x4;

    private static final int PROT_NONE  = 0x0;
    private static final int PROT_READ  = 0x1;
    private static final int PROT_WRITE = 0x2;
    private static final int PROT_EXEC  = 0x4;

    private static final int MAP_SHARED    = 0x1;
    private static final int MAP_PRIVATE   = 0x2;
    private static final int MAP_FIXED     = 0x10;
    private static final int MAP_ANONYMOUS = 0x1000;

    private static Pointer arg_addr;

    // qa flagging
    private KernelPointer qaFlags;
    private KernelPointer secFlags;
    private KernelPointer utokenFlags;
    private KernelPointer targetId;

    private SdkInit sdk;
    // old
    private LibKernel libKernel;
    private byte[] elfData = null;

    private void init() throws Exception {
        if (KernelReadWrite.getAccessor(getClass().getClassLoader()) instanceof KernelAccessorIPv6) {
            KernelAccessorIPv6 kernelAccessor = (KernelAccessorIPv6) KernelReadWrite.getAccessor(getClass().getClassLoader());

            Pointer payload_output_addr = Pointer.calloc(8);
            Pointer pipe_rw_fds = Pointer.calloc(8);
            Pointer kern_rw_fds = Pointer.calloc(8);

            arg_addr = Pointer.calloc(0x30);

            kern_rw_fds.write4(kernelAccessor.getMasterSock());
            kern_rw_fds.inc(4).write4(kernelAccessor.getVictimSock());

            pipe_rw_fds.write4(kernelAccessor.getPipeReadFd());
            pipe_rw_fds.inc(4).write4(kernelAccessor.getPipeWriteFd());

            arg_addr.write8(libKernel.addrOf("sceKernelDlsym").addr());
            arg_addr.inc(0x08).write8(pipe_rw_fds.addr());
            arg_addr.inc(0x10).write8(kern_rw_fds.addr());
            arg_addr.inc(0x28).write8(payload_output_addr.addr());

            try {
                arg_addr.inc(0x18).write8(kernelAccessor.getPipeAddr().addr());
                arg_addr.inc(0x20).write8(sdk.kernelBaseAddress);
            } catch (Throwable t) {
                arg_addr.inc(0x18).write8(0);
                arg_addr.inc(0x20).write8(0);
            }
        } else {
            throw new Exception("KernelAccessorIPv6 not found");
        }
    }


    @Override
    public void run() {
         this.libKernel = new LibKernel();
         this.sdk = null;
        final FileInputStream fileInputStream;
        try {
            File elfFile = null;

            try {
                sdk = SdkInit.init(true, true);
                int uid = libKernel.getuid();
                if (uid != 0) {
                    Status.println("Current user is not root. Aborting.");
                    return;
                }

                // load bdj.elf from usb root
                for(int i = 0; i < 8; i++) {
                    try {
                        File f = new File("/mnt/usb" + i + "/bdj.elf");
                        if (f.exists()) {
                            elfFile = f;
                            Status.println("Found bdj.elf on usb" + i);
                            break;
                        }
                    } catch (Exception ex) {
                        Status.println("Error searching for bdj.elf on usb" + i);
                    }
                }

                KernelPointer kbase = KernelPointer.valueOf(sdk.kernelBaseAddress, false);
                KernelOffsets o = sdk.kernelOffsets;
                qaFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_QA_FLAGS);
                secFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS);
                utokenFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_UTOKEN_FLAGS);
                targetId = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_TARGET_ID);

                Status.println("Original kernel values:");
                printFlags();
                // Switch to DMA if necessary
                if (sdk.switchToAgcKernelReadWrite(true)) {
                    Status.println("Switched to AGC-based kernel r/w");
                }
                int qaFlagsVal = qaFlags.read4();
                qaFlags.write4(qaFlagsVal | 0x10300);
                int secFlagsVal = secFlags.read4();
                secFlags.write4(secFlagsVal | 0x14);
                byte targetIdVal = targetId.read1();
                targetId.write1((byte) 0x82);
                byte utokenVal = utokenFlags.read1();
                utokenFlags.write1((byte) ((utokenVal | 0x01) & 0xFF));
                Status.println("New kernel values:");
                printFlags();
            } finally {
                if (sdk != null) {
                    sdk.restoreNonAgcKernelReadWrite();
                    Status.println("Switched back to original kernel r/w");
                }
            }

            if (elfFile == null) {
                Status.println("No bdj.elf found!");
                return;
            }

            this.elfData = new byte[(int) elfFile.length()];
            int read = new FileInputStream(elfFile).read(this.elfData);
            Status.println("# bytes of bdj.elf: " + read);

            File procDumpBeforeSetup = new File(elfFile.getParentFile(), "before_setup.procdump");
            if (procDumpBeforeSetup.exists()) {
                procDumpBeforeSetup.delete();
            }
            Status.println("Dumping current process to " + procDumpBeforeSetup.getAbsolutePath());
            DumpCurProcUtil.dumpCurProcToFile(procDumpBeforeSetup, libKernel, sdk);

            // try to init and run elf
            init();

            File procDumpAfterSetup = new File(elfFile.getParentFile(), "after_setup.procdump");
            if (procDumpAfterSetup.exists()) {
                procDumpAfterSetup.delete();
            }
            Status.println("Dumping current process to " + procDumpAfterSetup.getAbsolutePath());
            DumpCurProcUtil.dumpCurProcToFile(procDumpAfterSetup, libKernel, sdk);

            Status.println("Init of elfloader successful! Trying to run elf...");
            runElf(this.elfData);

            File procDumpPostRun = new File(elfFile.getParentFile(), "post_run.procdump");
            if (procDumpPostRun.exists()) {
                procDumpPostRun.delete();
            }
            Status.println("Dumping current process to " + procDumpPostRun.getAbsolutePath());
            DumpCurProcUtil.dumpCurProcToFile(procDumpPostRun, libKernel, sdk);

        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (sdk != null) {
                sdk.restoreNonAgcKernelReadWrite();
            }
            libKernel.closeLibrary();
        }
    }

    public void runElf(byte[] bytes) throws Exception {
        OutputStream os = new FileOutputStream("/dev/null");
        try {
            runElf(bytes, os);
        } finally {
            os.close();
        }
    }

    private long ROUND_PG(long val) {
        return (val + 0x3FFF) & 0xFFFFC000;
    }

    private static long TRUNC_PG(long val) {
        return val & 0xFFFFC000;
    }

    private static int PFLAGS(int p_flags) {
        int prot = 0;

        if((p_flags & PF_X) == PF_X) {
            prot |= PROT_EXEC;
        }
        if((p_flags & PF_W) == PF_W) {
            prot |= PROT_WRITE;
        }
        if((p_flags & PF_R) == PF_R) {
            prot |= PROT_READ;
        }

        return prot;
    }

    private void r_relative(Pointer base_addr, Pointer rela_addr) throws Exception {
        long r_offset = rela_addr.inc(OFF_RELA_OFFSET).read8();
        long r_addend = rela_addr.inc(OFF_RELA_OFFSET).read8();

        base_addr.inc(r_offset).write8(base_addr.addr() + r_addend);
    }

    private void pt_load(Pointer elf_addr, Pointer base_addr, Pointer phdr_addr)
            throws Exception {
        long p_offset = phdr_addr.inc(OFF_PHDR_OFFSET).read8();
        long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
        long p_filesz = phdr_addr.inc(OFF_PHDR_FILESZ).read8();
        long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();

        if(p_memsz == 0) {
            return;
        }

        long memsz = ROUND_PG(p_memsz);
        Pointer addr = base_addr.inc(p_vaddr);

        addr = libKernel.mmap(addr, memsz,
                PROT_READ | PROT_WRITE,
                MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
                -1, 0);

        if(addr.addr() == -1) {
            throw new Exception("pt_load: mmap returned -1");
        }

        if(p_filesz > 0) {
            elf_addr.inc(p_offset).copyTo(addr, 0, (int)p_filesz);
        }
    }

    private void pt_reload(Pointer base_addr, Pointer phdr_addr)
            throws Exception {
        long p_offset = phdr_addr.inc(OFF_PHDR_OFFSET).read8();
        long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
        long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
        int p_flags = phdr_addr.inc(OFF_PHDR_FLAGS).read4();

        Pointer addr = base_addr.inc(p_vaddr);
        long memsz = ROUND_PG(p_memsz);
        int prot = PFLAGS(p_flags);

        Pointer ret_addr = Pointer.calloc(8);
        Pointer data = Pointer.calloc(memsz);

        int alias_fd = -1;
        int shm_fd = -1;

        // Backup data
        addr.copyTo(data, 0, (int)memsz);

        try {
            // Create shm with executable permissions.
            if(libKernel.jitCreateSharedMemory(0, memsz,
                    prot | PROT_READ | PROT_WRITE,
                    ret_addr.addr()) == 0) {
                shm_fd = ret_addr.read4();
            } else {
                throw new Exception("pt_reload: jitCreateSharedMemory failed");
            }

            // Map shm into an executable address space.
            if(libKernel.mmap(addr, memsz, prot,
                    MAP_FIXED | MAP_PRIVATE, shm_fd, 0).addr() == -1) {
                throw new Exception("pt_reload: mmap shm failed");
            }

            // Create an shm alias fd with write permissions.
            if(libKernel.jitCreateAliasOfSharedMemory(shm_fd,
                    PROT_READ | PROT_WRITE,
                    ret_addr.addr()) == 0) {
                alias_fd = ret_addr.read4();
            } else {
                throw new Exception("pt_reload: jitCreateAliasOfSharedMemory failed");
            }

            // Map shm alias into a writable address space.
            addr = libKernel.mmap(Pointer.NULL, memsz, PROT_READ | PROT_WRITE,
                    MAP_SHARED, alias_fd, 0);
            if(addr.addr() == -1) {
                throw new Exception("pt_reload: mmap shm alias failed");
            }

            // Restore data
            addr.write(data.read((int)memsz));

            libKernel.munmap(addr, memsz);
        } finally {
            // Cleanup resources.
            ret_addr.free();
            data.free();

            if(alias_fd != -1) {
                libKernel.close(alias_fd);
            }
            if(shm_fd != -1) {
                libKernel.close(shm_fd);
            }
        }
    }

    public void runElf(byte[] elf_bytes, OutputStream os) throws Exception {
        Pointer elf_addr = Pointer.NULL;

        Pointer base_addr = Pointer.NULL;
        long base_size = 0;

        long min_vaddr = -1;
        long max_vaddr = -1;

        if(elf_bytes[0] != (byte)0x7f || elf_bytes[1] != (byte)0x45 ||
                elf_bytes[2] != (byte)0x4c || elf_bytes[3] != (byte)0x46) {
            throw new IOException("Invalid ELF file");
        }
        Status.println("ELF validity check passed");

        try {
            elf_addr = Pointer.calloc(elf_bytes.length);
            for(int i = 0; i < elf_bytes.length; i++) {
                 elf_addr.inc(i).write1(elf_bytes[i]);
            }
            Status.println("ELF bytes written to " + elf_addr);

            short e_type =  elf_addr.inc(OFF_EHDR_TYPE).read2();
            long e_entry  = elf_addr.inc(OFF_EHDR_ENTRY).read8();
            long e_phoff  = elf_addr.inc(OFF_EHDR_PHOFF).read8();
            long e_shoff  = elf_addr.inc(OFF_EHDR_SHOFF).read8();
            short e_phnum = elf_addr.inc(OFF_EHDR_PHNUM).read2();
            short e_shnum = elf_addr.inc(OFF_EHDR_SHNUM).read2();

            // Compute size of virtual memory region.
            for(int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
                long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();

                if(p_vaddr < min_vaddr || min_vaddr == -1) {
                    min_vaddr = p_vaddr;
                }

                if(max_vaddr < p_vaddr + p_memsz) {
                    max_vaddr = p_vaddr + p_memsz;
                }
            }
            Status.println("Virtual memory region computed");

            min_vaddr = TRUNC_PG(min_vaddr);
            max_vaddr = ROUND_PG(max_vaddr);
            base_size = max_vaddr - min_vaddr;

            int flags = MAP_PRIVATE | MAP_ANONYMOUS;
            if(e_type == ET_DYN) {
                base_addr = Pointer.NULL;
            } else if(e_type == ET_EXEC) {
                base_addr = Pointer.valueOf(min_vaddr);
                flags |= MAP_FIXED;
            } else {
                throw new IOException("Unsupported ELF file");
            }

            // Reserve an address space of sufficient size.
            base_addr = libKernel.mmap(base_addr, base_size, PROT_NONE,
                    flags, -1, 0);
            if(base_addr.addr() == -1) {
                throw new Exception("runElf: mmap failed");
            }
            Status.println("Address space reserved");

            // Parse program headers.
            for(int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                int p_type = phdr_addr.inc(OFF_PHDR_TYPE).read4();

                if(p_type == PT_LOAD) {
                    Status.println("pt_load started...");
                    pt_load(elf_addr, base_addr, phdr_addr);
                    Status.println("pt_load finished.");
                }
            }
            Status.println("Program headers parsed");

            // Apply relocations.
            for(int i = 0; i < e_shnum; i++) {
                Pointer shdr_addr =  elf_addr.inc(e_shoff).inc(i * SIZE_SHDR);
                int sh_type = shdr_addr.inc(OFF_SHDR_TYPE).read4();

                if (sh_type != SHT_RELA) {
                    continue;
                }

                long sh_offset = shdr_addr.inc(OFF_SHDR_OFFSET).read8();
                long sh_size = shdr_addr.inc(OFF_SHDR_SIZE).read8();

                for (int j = 0; j < sh_size/SIZE_RELA; j++) {
                    Pointer rela_addr = elf_addr.inc(sh_offset).inc(SIZE_RELA * j);
                    long r_info = rela_addr.inc(OFF_RELA_INFO).read8();
                    if(r_info == R_X86_64_RELATIVE) {
                        r_relative(base_addr, rela_addr);
                    }
                }
            }
            Status.println("Relocations applied");

            // Set protection bits on mapped segments.
            for(int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
                long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
                int p_type = phdr_addr.inc(OFF_PHDR_TYPE).read4();
                int p_flags = phdr_addr.inc(OFF_PHDR_FLAGS).read4();

                if(p_type != PT_LOAD || p_memsz == 0) {
                    continue;
                }

                if((p_flags & PF_X) == PF_X) {
                    Status.println("pt_reload started...");
                    pt_reload(base_addr, phdr_addr);
                    Status.println("pt_reload finished");
                    continue;
                }

                Pointer addr = base_addr.inc(p_vaddr); // base_addr + p_vaddr;
                long memsz = ROUND_PG(p_memsz);
                int prot = PFLAGS(p_flags);
                if(libKernel.mprotect(addr, memsz, prot) != 0) {
                    throw new Exception("runElf: mmap failed");
                }
            }
            Status.println("Protection bits set");

            if(base_addr.addr() != -1) {
                long args[] = new long[6];

                // Invoke entry point.
                args[0] = arg_addr.addr();
                args[1] = 0;
                args[2] = 0;
                args[3] = 0;
                args[4] = 0;
                args[5] = 0;
                Status.println("Invoking entry point...");
                libKernel.call(base_addr.inc(e_entry), args);
                Status.println("Loaded elf finished.");
            } else {
                throw new IOException("Invalid ELF file");
            }
        } finally {
            if(elf_addr.addr() != 0) {
                elf_addr.free();
            }
            if(base_addr.addr() != -1) {
                libKernel.munmap(base_addr, base_size);
            }
        }
    }

    private void printFlags() {
        Status.println("  QA Flags: 0x" + Integer.toHexString(qaFlags.read4()));
        Status.println("  Security Flags: 0x" + Integer.toHexString(secFlags.read4()));
        Status.println("  Utoken Flags: 0x" + Integer.toHexString(utokenFlags.read1() & 0xFF));
        Status.println("  Target ID: 0x" + Integer.toHexString(targetId.read1() & 0xFF));
    }
}
