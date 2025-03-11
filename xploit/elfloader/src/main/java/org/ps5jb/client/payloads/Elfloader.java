package org.ps5jb.client.payloads;

import org.ps5jb.client.utils.init.SdkInit;
import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Library;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.kernel.KernelAccessorIPv6;
import org.ps5jb.sdk.core.kernel.KernelOffsets;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.lib.LibKernel;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

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
    private static final int OFF_SHDR_ADDR   = 0x20;
    private static final int OFF_SHDR_SIZE   = 0x28;

    private static final int OFF_RELA_OFFSET = 0x00;
    private static final int OFF_RELA_INFO   = 0x08;
    private static final int OFF_RELA_ADDEND = 0x10;

    private static final int SIZE_PHDR = 0x38;
    private static final int SIZE_EHDR = 0x40;
    private static final int SIZE_SHDR = 0x40;
    private static final int SIZE_RELA = 0x18;

    private static final int ET_EXEC = 2;
    private static final int ET_DYN  = 3;

    private static final int PT_LOAD    = 0x01;
    private static final int PT_DYNAMIC = 0x02;
    private static final int PT_INTERP  = 0x03;

    private static final int SHT_RELA      = 4;
    private static final int SHT_INIT_ARRAY = 0x0e;

    private static final int R_X86_64_RELATIVE = 8;
    private static final int R_X86_64_GLOB_DAT = 6;
    private static final int R_X86_64_JUMP_SLOT = 7;

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

    private KernelPointer qaFlags;
    private KernelPointer secFlags;
    private KernelPointer utokenFlags;
    private KernelPointer targetId;

    private SdkInit sdk;
    private LibKernel libKernel;
    private byte[] elfData = null;
    private Map loadedLibraries = new HashMap();

    private long min_vaddr = -1;
    private long max_vaddr = -1;
    private Pointer base_addr = Pointer.NULL;
    private long base_size = 0;
    private boolean skipDynamicLibraries = true;

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

    public void run() {
        this.libKernel = new LibKernel();
        this.sdk = null;
        try {
            File elfFile = null;

            try {
                sdk = SdkInit.init(true, true);
                int uid = libKernel.getuid();
                if (uid != 0) {
                    return;
                }

                for (int i = 0; i < 8; i++) {
                    try {
                        File f = new File("/mnt/usb" + i + "/bdj.elf");
                        if (f.exists()) {
                            elfFile = f;
                            break;
                        }
                    } catch (Exception ex) {
                    }
                }

                KernelPointer kbase = KernelPointer.valueOf(sdk.kernelBaseAddress, false);
                KernelOffsets o = sdk.kernelOffsets;
                qaFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_QA_FLAGS);
                secFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_SECURITY_FLAGS);
                utokenFlags = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_UTOKEN_FLAGS);
                targetId = kbase.inc(o.OFFSET_KERNEL_DATA + o.OFFSET_KERNEL_DATA_BASE_TARGET_ID);

                int qaFlagsVal = qaFlags.read4();
                qaFlags.write4(qaFlagsVal | 0x10300);
                int secFlagsVal = secFlags.read4();
                secFlags.write4(secFlagsVal | 0x14);
                byte targetIdVal = targetId.read1();
                targetId.write1((byte) 0x82);
                byte utokenVal = utokenFlags.read1();
                utokenFlags.write1((byte) ((utokenVal | 0x01) & 0xFF));

                loadedLibraries.put("libKernel", libKernel);
            } finally {
                if (sdk != null) {
                    sdk.restoreNonAgcKernelReadWrite();
                }
            }

            if (elfFile == null) {
                return;
            }

            this.elfData = new byte[(int) elfFile.length()];
            new FileInputStream(elfFile).read(this.elfData);

            File procDumpBeforeSetup = new File(elfFile.getParentFile(), "before_setup.procdump");
            if (procDumpBeforeSetup.exists()) {
                procDumpBeforeSetup.delete();
            }
            DumpCurProcUtil.dumpCurProcToFile(procDumpBeforeSetup, libKernel, sdk);

            init();

            File procDumpAfterSetup = new File(elfFile.getParentFile(), "after_setup.procdump");
            if (procDumpAfterSetup.exists()) {
                procDumpAfterSetup.delete();
            }
            DumpCurProcUtil.dumpCurProcToFile(procDumpAfterSetup, libKernel, sdk);

            runElf(this.elfData);

            File procDumpPostRun = new File(elfFile.getParentFile(), "post_run.procdump");
            if (procDumpPostRun.exists()) {
                procDumpPostRun.delete();
            }
            DumpCurProcUtil.dumpCurProcToFile(procDumpPostRun, libKernel, sdk);

        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (sdk != null) {
                sdk.restoreNonAgcKernelReadWrite();
            }
            for (Iterator iter = loadedLibraries.values().iterator(); iter.hasNext(); ) {
                Library lib = (Library) iter.next();
                lib.closeLibrary();
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
        if ((p_flags & PF_X) == PF_X) prot |= PROT_EXEC;
        if ((p_flags & PF_W) == PF_W) prot |= PROT_WRITE;
        if ((p_flags & PF_R) == PF_R) prot |= PROT_READ;
        return prot;
    }

    private void r_relative(Pointer base_addr, Pointer rela_addr) throws Exception {
        long r_offset = rela_addr.inc(OFF_RELA_OFFSET).read8();
        long r_addend = rela_addr.inc(OFF_RELA_ADDEND).read8();
        this.base_addr.inc(r_offset).write8(this.base_addr.addr() + r_addend);
    }

    private void pt_load(Pointer elf_addr, Pointer base_addr, Pointer phdr_addr) throws Exception {
        long p_offset = phdr_addr.inc(OFF_PHDR_OFFSET).read8();
        long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
        long p_filesz = phdr_addr.inc(OFF_PHDR_FILESZ).read8();
        long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
        if (p_memsz == 0) {
            return;
        }
        long memsz = ROUND_PG(p_memsz);
        Pointer addr = this.base_addr.inc(p_vaddr);
        addr = libKernel.mmap(addr, memsz, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (addr.addr() == -1) {
            throw new Exception("pt_load: mmap returned -1");
        }
        if (p_filesz > 0) {
            elf_addr.inc(p_offset).copyTo(addr, 0, (int) p_filesz);
        }
    }

    private void pt_dynamic(Pointer elf_addr, Pointer base_addr, Pointer phdr_addr) throws Exception {
        long p_offset = phdr_addr.inc(OFF_PHDR_OFFSET).read8();
        long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
        long p_filesz = phdr_addr.inc(OFF_PHDR_FILESZ).read8();
        long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
        if (p_memsz == 0) {
            return;
        }
        long memsz = ROUND_PG(p_memsz);
        Pointer addr = this.base_addr.inc(p_vaddr);
        addr = libKernel.mmap(addr, memsz, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (addr.addr() == -1) {
            throw new Exception("pt_dynamic: mmap returned -1");
        }
        if (p_filesz > 0) {
            elf_addr.inc(p_offset).copyTo(addr, 0, (int) p_filesz);
        }
    }

    private void pt_reload(Pointer base_addr, Pointer phdr_addr) throws Exception {
        long p_offset = phdr_addr.inc(OFF_PHDR_OFFSET).read8();
        long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
        long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
        int p_flags = phdr_addr.inc(OFF_PHDR_FLAGS).read4();
        Pointer addr = this.base_addr.inc(p_vaddr);
        long memsz = ROUND_PG(p_memsz);
        int prot = PFLAGS(p_flags);
        if ((p_flags & PF_X) == PF_X) prot |= PROT_EXEC;
        Pointer ret_addr = Pointer.calloc(8);
        Pointer data = Pointer.calloc(memsz);
        addr.copyTo(data, 0, (int) memsz);
        int alias_fd = -1;
        int shm_fd = -1;
        try {
            if (libKernel.jitCreateSharedMemory(0, memsz, prot | PROT_READ | PROT_WRITE, ret_addr.addr()) == 0) {
                shm_fd = ret_addr.read4();
            } else {
                throw new Exception("pt_reload: jitCreateSharedMemory failed");
            }
            if (libKernel.mmap(addr, memsz, prot, MAP_FIXED | MAP_PRIVATE, shm_fd, 0).addr() == -1) {
                throw new Exception("pt_reload: mmap shm failed");
            }
            if (libKernel.jitCreateAliasOfSharedMemory(shm_fd, PROT_READ | PROT_WRITE, ret_addr.addr()) == 0) {
                alias_fd = ret_addr.read4();
            } else {
                throw new Exception("pt_reload: jitCreateAliasOfSharedMemory failed");
            }
            addr = libKernel.mmap(Pointer.NULL, memsz, PROT_READ | PROT_WRITE, MAP_SHARED, alias_fd, 0);
            if (addr.addr() == -1) {
                throw new Exception("pt_reload: mmap shm alias failed");
            }
            addr.write(data.read((int) memsz));
            libKernel.munmap(addr, memsz);
        } finally {
            ret_addr.free();
            data.free();
            if (alias_fd != -1) {
                libKernel.close(alias_fd);
            }
            if (shm_fd != -1) {
                libKernel.close(shm_fd);
            }
        }
    }

    public void runElf(byte[] elf_bytes, OutputStream os) throws Exception {
        Pointer elf_addr = Pointer.NULL;
        Pointer dynamic_section_addr = null;
        boolean hasCRT = false;

        if (elf_bytes[0] != (byte) 0x7f || elf_bytes[1] != (byte) 0x45 || elf_bytes[2] != (byte) 0x4c || elf_bytes[3] != (byte) 0x46) {
            throw new IOException("Invalid ELF file");
        }

        try {
            elf_addr = Pointer.calloc(elf_bytes.length);
            for (int i = 0; i < elf_bytes.length; i++) {
                elf_addr.inc(i).write1(elf_bytes[i]);
            }

            short e_type = elf_addr.inc(OFF_EHDR_TYPE).read2();
            long e_entry = elf_addr.inc(OFF_EHDR_ENTRY).read8();
            long e_phoff = elf_addr.inc(OFF_EHDR_PHOFF).read8();
            long e_shoff = elf_addr.inc(OFF_EHDR_SHOFF).read8();
            short e_phnum = elf_addr.inc(OFF_EHDR_PHNUM).read2();
            short e_shnum = elf_addr.inc(OFF_EHDR_SHNUM).read2();

            if (e_type == ET_DYN) {
            } else if (e_type == ET_EXEC) {
            } else {
                throw new IOException("Unsupported ELF file");
            }

            for (int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
                long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
                if (p_vaddr < this.min_vaddr || this.min_vaddr == -1) this.min_vaddr = p_vaddr;
                if (this.max_vaddr < p_vaddr + p_memsz) this.max_vaddr = p_vaddr + p_memsz;
            }
            this.min_vaddr = TRUNC_PG(this.min_vaddr);
            this.max_vaddr = ROUND_PG(this.max_vaddr);
            this.base_size = this.max_vaddr - this.min_vaddr;

            int flags = MAP_PRIVATE | MAP_ANONYMOUS;
            if (e_type == ET_DYN) {
                this.base_addr = Pointer.NULL;
            } else if (e_type == ET_EXEC) {
                this.base_addr = Pointer.valueOf(this.min_vaddr);
                flags |= MAP_FIXED;
            }
            this.base_addr = libKernel.mmap(this.base_addr, this.base_size, PROT_NONE, flags, -1, 0);
            if (this.base_addr.addr() == -1) {
                throw new Exception("runElf: mmap failed");
            }

            for (int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                int p_type = phdr_addr.inc(OFF_PHDR_TYPE).read4();
                if (p_type == PT_LOAD) {
                    pt_load(elf_addr, this.base_addr, phdr_addr);
                } else if (p_type == PT_DYNAMIC) {
                    pt_dynamic(elf_addr, this.base_addr, phdr_addr);
                    dynamic_section_addr = this.base_addr.inc(phdr_addr.inc(OFF_PHDR_VADDR).read8());
                } else if (p_type == PT_INTERP) {
                    long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
                    Pointer interp_addr = this.base_addr.inc(p_vaddr);
                    String interp_name = interp_addr.readString(new Integer(256));
                    hasCRT = true;
                }
            }

            if (!hasCRT) {
                for (int i = 0; i < e_shnum; i++) {
                    Pointer shdr_addr = elf_addr.inc(e_shoff).inc(i * SIZE_SHDR);
                    int sh_type = shdr_addr.inc(OFF_SHDR_TYPE).read4();
                    if (sh_type == SHT_INIT_ARRAY) {
                        hasCRT = true;
                        break;
                    }
                }
            }

            if (hasCRT && skipDynamicLibraries) {
                provideFallbackSymbols();
            }

            if (dynamic_section_addr != null && !skipDynamicLibraries) {
                Pointer dyn = dynamic_section_addr;
                long strtab_addr = 0;
                long strtab_size = 0;
                List neededOffsets = new ArrayList();
                Map neededLibraries = new HashMap();

                while (dyn.read8() != 0) {
                    long d_tag = dyn.read8();
                    long d_val = dyn.inc(8).read8();
                    if (d_tag == 0x5) {
                        strtab_addr = this.base_addr.addr() + d_val;
                    } else if (d_tag == 0x6) {
                        strtab_size = d_val;
                    } else if (d_tag == 0x1) {
                        neededOffsets.add(new Long(d_val));
                    }
                    dyn = dyn.inc(16);
                }

                if (strtab_addr != 0 && !neededOffsets.isEmpty()) {
                    for (Iterator iter = neededOffsets.iterator(); iter.hasNext(); ) {
                        Long offset = (Long) iter.next();
                        String library_name = new Pointer(strtab_addr + offset.longValue()).readString(new Integer(256));
                        if (library_name != null && library_name.trim().length() > 0) {
                            if (library_name.equals("libkernel_web.sprx")) {
                                neededLibraries.put(library_name, Boolean.FALSE);
                            } else {
                            }
                        }
                    }
                }

                if (!neededLibraries.isEmpty()) {
                    for (Iterator iter = neededLibraries.keySet().iterator(); iter.hasNext(); ) {
                        String library_name = (String) iter.next();
                        try {
                            loadLibrary(library_name);
                            neededLibraries.put(library_name, Boolean.TRUE);
                        } catch (Exception e) {
                        }
                    }
                    boolean allLoaded = true;
                    for (Iterator iter = neededLibraries.values().iterator(); iter.hasNext(); ) {
                        if (!((Boolean) iter.next()).booleanValue()) {
                            allLoaded = false;
                            break;
                        }
                    }
                }
            } else {
            }

            for (int i = 0; i < e_shnum; i++) {
                Pointer shdr_addr = elf_addr.inc(e_shoff).inc(i * SIZE_SHDR);
                int sh_type = shdr_addr.inc(OFF_SHDR_TYPE).read4();
                if (sh_type != SHT_RELA) {
                    continue;
                }
                long sh_offset = shdr_addr.inc(OFF_SHDR_OFFSET).read8();
                long sh_size = shdr_addr.inc(OFF_SHDR_SIZE).read8();
                int rela_count = (int) (sh_size / SIZE_RELA);
                for (int j = 0; j < rela_count; j++) {
                    Pointer rela_addr = elf_addr.inc(sh_offset).inc(SIZE_RELA * j);
                    long r_info = rela_addr.inc(OFF_RELA_INFO).read8();
                    int r_type = (int) (r_info & 0xFFFFFFFFL);
                    int symbolIndex = (int) (r_info >> 32);
                    if (r_type == R_X86_64_RELATIVE) {
                        r_relative(this.base_addr, rela_addr);
                    } else if (r_type == R_X86_64_GLOB_DAT || r_type == R_X86_64_JUMP_SLOT) {
                        long r_offset = rela_addr.inc(OFF_RELA_OFFSET).read8();
                        long r_addend = rela_addr.inc(OFF_RELA_ADDEND).read8();
                        String symbolName = getSymbolNameFromDynamic(elf_addr, dynamic_section_addr, symbolIndex);
                        if (symbolName != null) {
                            Pointer symbolAddr = null;
                            for (Iterator iter = loadedLibraries.values().iterator(); iter.hasNext(); ) {
                                Library lib = (Library) iter.next();
                                try {
                                    symbolAddr = lib.addrOf(symbolName);
                                    if (symbolAddr != null && symbolAddr.addr() != 0) {
                                        break;
                                    }
                                } catch (Exception e) {
                                    continue;
                                }
                            }
                            if (symbolAddr != null && symbolAddr.addr() != 0) {
                                this.base_addr.inc(r_offset).write8(symbolAddr.addr() + r_addend);
                            }
                        }
                    }
                }
            }

            for (int i = 0; i < e_phnum; i++) {
                Pointer phdr_addr = elf_addr.inc(e_phoff).inc(i * SIZE_PHDR);
                long p_memsz = phdr_addr.inc(OFF_PHDR_MEMSZ).read8();
                long p_vaddr = phdr_addr.inc(OFF_PHDR_VADDR).read8();
                int p_type = phdr_addr.inc(OFF_PHDR_TYPE).read4();
                int p_flags = phdr_addr.inc(OFF_PHDR_FLAGS).read4();
                if (p_type != PT_LOAD && p_type != PT_DYNAMIC || p_memsz == 0) {
                    continue;
                }
                if ((p_flags & PF_X) == PF_X) {
                    pt_reload(this.base_addr, phdr_addr);
                    continue;
                }
                Pointer addr = this.base_addr.inc(p_vaddr);
                long memsz = ROUND_PG(p_memsz);
                int prot = PFLAGS(p_flags);
                if (libKernel.mprotect(addr, memsz, prot) != 0) {
                    throw new Exception("runElf: mprotect failed");
                }
            }

            if (this.base_addr.addr() != -1) {
                long entry_point = this.base_addr.inc(e_entry).addr();
                if (entry_point <= 0) {
                    throw new Exception("Invalid entry point address");
                }
                if (arg_addr.addr() <= 0) {
                    throw new Exception("Invalid arg_addr");
                }
                long args[] = new long[1];
                args[0] = arg_addr.addr();
                libKernel.call(this.base_addr.inc(e_entry), args);
            } else {
                throw new IOException("Invalid ELF file");
            }
        } finally {
            if (elf_addr.addr() != 0) {
                elf_addr.free();
            }
            if (this.base_addr.addr() != -1) {
                libKernel.munmap(this.base_addr, this.base_size);
            }
        }
    }

    private void loadLibrary(String libraryName) throws Exception {
        String libraryPath = libraryName.endsWith(".sprx") ? "/system/common/lib/" + libraryName : "/system/common/lib/" + libraryName + ".sprx";
        File libraryFile = new File(libraryPath);
        if (!libraryFile.exists()) {
            throw new Exception("Library not found: " + libraryName);
        }
        Library lib = new Library(libraryPath);
        loadedLibraries.put(libraryName, lib);
    }

    private void resolveDynamicSymbols(Pointer base_addr) throws Exception {
        if (loadedLibraries.isEmpty()) {
            return;
        }

        Map librarySymbols = new HashMap();
        librarySymbols.put("libkernel_web.sprx", new String[]{"getpid", "kill", "waitpid", "munmap", "mprotect", "mmap", "dup", "sceKernelSendNotificationRequest"});
        librarySymbols.put("libSceLibcInternal.sprx", new String[]{"malloc", "free", "strlen", "strcmp", "memcpy", "strcpy", "strcat", "strerror", "memset", "vsnprintf"});
        librarySymbols.put("libSceNet.sprx", new String[]{});
        librarySymbols.put("libKernel", new String[]{});

        for (Iterator iter = loadedLibraries.entrySet().iterator(); iter.hasNext(); ) {
            Map.Entry entry = (Map.Entry) iter.next();
            String libName = (String) entry.getKey();
            Library lib = (Library) entry.getValue();
            String[] symbols = (String[]) librarySymbols.get(libName);
            if (symbols == null) symbols = new String[0];
            for (String symbol : symbols) {
                try {
                    Pointer symbolAddr = lib.addrOf(symbol);
                } catch (Exception e) {
                }
            }
        }
    }

    private String getSymbolNameFromDynamic(Pointer elf_addr, Pointer dynamic_section_addr, int symbolIndex) throws Exception {
        long dynsym_addr = 0;
        long dynstr_addr = 0;
        final int SIZEOF_DYN = 16;
        final int OFF_D_TAG = 0;
        final int OFF_D_VAL = 8;
        final long DT_SYMTAB = 4;
        final long DT_STRTAB = 5;
        final long DT_NULL = 0;

        for (int i = 0; ; i++) {
            Pointer dyn_entry = dynamic_section_addr.inc(i * SIZEOF_DYN);
            long d_tag = dyn_entry.inc(OFF_D_TAG).read8();
            long d_val = dyn_entry.inc(OFF_D_VAL).read8();
            if (d_tag == DT_NULL) break;
            if (d_tag == DT_SYMTAB) dynsym_addr = d_val;
            else if (d_tag == DT_STRTAB) dynstr_addr = d_val;
        }

        if (dynsym_addr == 0 || dynstr_addr == 0) {
            return null;
        }

        Pointer dynsym_table = this.base_addr.inc(dynsym_addr);
        Pointer dynstr_table = this.base_addr.inc(dynstr_addr);

        try {
            final int SIZEOF_SYM = 24;
            final int OFF_ST_NAME = 0;
            Pointer symbol_entry = dynsym_table.inc(symbolIndex * SIZEOF_SYM);
            int st_name_offset = symbol_entry.inc(OFF_ST_NAME).read4();
            Pointer symbol_name_ptr = dynstr_table.inc(st_name_offset);
            String symbol_name = readString(symbol_name_ptr);
            if (symbol_name == null || symbol_name.length() == 0) {
                return null;
            }
            return symbol_name;
        } catch (Exception e) {
            return null;
        }
    }

    private String readString(Pointer ptr) throws Exception {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 256; i++) {
            byte b = ptr.inc(i).read1();
            if (b == 0) break;
            sb.append((char) b);
        }
        return sb.toString();
    }

    private void provideFallbackSymbols() {
        try {
            Pointer memsetAddr = libKernel.addrOf("sceKernelZeroMemory");
        } catch (Exception e) {
        }
    }

    private void printFlags() {
        Status.println("  QA Flags: 0x" + Integer.toHexString(qaFlags.read4()));
        Status.println("  Security Flags: 0x" + Integer.toHexString(secFlags.read4()));
        Status.println("  Utoken Flags: 0x" + Integer.toHexString(utokenFlags.read1() & 0xFF));
        Status.println("  Target ID: 0x" + Integer.toHexString(targetId.read1() & 0xFF));
    }
}