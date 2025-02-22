package org.ps5jb.client.payloads;

import org.ps5jb.loader.Config;
import org.ps5jb.loader.KernelReadWrite;
import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.SdkException;
import org.ps5jb.sdk.core.kernel.KernelAccessorIPv6;
import org.ps5jb.sdk.include.sys.MMan;
import org.ps5jb.sdk.include.sys.mman.MappingFlag;
import org.ps5jb.sdk.include.sys.mman.ProtectionFlag;
import org.ps5jb.sdk.lib.LibKernel;

import java.io.File;
import java.io.FileInputStream;


public class Elfloader implements Runnable {

    private static long shadow_mapping_addr = 0x920100000L;
    private static long mapping_addr = 0x926100000L;

    private LibKernel libKernel;
    private MMan mman;

    private byte[] elfData = null;

    private long elf_entry_point = -1;
    private Pointer payloadout = null;
    private long thr_handle = -1;

    @Override
    public void run() {
         this.libKernel = new LibKernel();
         this.mman = new MMan(this.libKernel);
        final FileInputStream fileInputStream;
        try {
            final File elfFile = new File(Config.getLoaderPayloadPath(), "elfldr.elf");
            this.elfData = new byte[(int) elfFile.length()];
            int read = new FileInputStream(elfFile).read(this.elfData);
            Status.println("Bytes of elfldr.elf: " + Integer.toHexString(read));

            this.parse(Pointer.valueOf(Pointer.addrOf(this.elfData)));
            this.runLoader();


            while (true) {
                Thread.yield();
                Thread.sleep(3000);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            libKernel.closeLibrary();
        }
    }

    private void parse(final Pointer elfDataPointer) throws SdkException {
        // ELF sizes and offsets
        final long SIZE_ELF_HEADER = 0x40;
        final long SIZE_ELF_PROGRAM_HEADER = 0x38;
        final long SIZE_ELF_SECTION_HEADER = 0x40;

        final long OFFSET_ELF_HEADER_ENTRY = 0x18;
        final long OFFSET_ELF_HEADER_PHOFF = 0x20;
        final long OFFSET_ELF_HEADER_SHOFF = 0x28;
        final long OFFSET_ELF_HEADER_PHNUM = 0x38;
        final long OFFSET_ELF_HEADER_SHNUM = 0x3c;

        final long OFFSET_PROGRAM_HEADER_TYPE = 0x00;
        final long OFFSET_PROGRAM_HEADER_FLAGS = 0x04;
        final long OFFSET_PROGRAM_HEADER_OFFSET = 0x08;
        final long OFFSET_PROGRAM_HEADER_VADDR = 0x10;
        final long OFFSET_PROGRAM_HEADER_FILESZ = 0x20;
        final long OFFSET_PROGRAM_HEADER_MEMSZ = 0x28;

        final long OFFSET_SECTION_HEADER_TYPE = 0x4;
        final long OFFSET_SECTION_HEADER_OFFSET = 0x18;
        final long OFFSET_SECTION_HEADER_SIZE = 0x20;

        final long OFFSET_RELA_OFFSET = 0x00;
        final long OFFSET_RELA_INFO = 0x08;
        final long OFFSET_RELA_ADDEND = 0x10;

        final long SHT_RELA = 0x4;
        final long RELA_ENTSIZE = 0x18;

        final long PF_X = 1;

        // ELF program header types
        final long ELF_PT_LOAD = 0x01;
        final long ELF_PT_DYNAMIC = 0x02;

        // ELF dynamic table types
        final long ELF_DT_NULL = 0x00;
        final long ELF_DT_RELA = 0x07;
        final long ELF_DT_RELASZ = 0x08;
        final long ELF_DT_RELAENT = 0x09;
        final long ELF_R_AMD64_RELATIVE = 0x08;

        final Pointer elf_store = elfDataPointer;

        long elf_entry = elf_store.read4(OFFSET_ELF_HEADER_ENTRY);
        this.elf_entry_point = mapping_addr + elf_entry;


        final long elf_program_headers_offset = elf_store.read4(OFFSET_ELF_HEADER_PHOFF);
        final long elf_program_headers_num = elf_store.read2(OFFSET_ELF_HEADER_PHNUM);

        final long elf_section_headers_offset = elf_store.read4(OFFSET_ELF_HEADER_SHOFF);
        final long elf_section_headers_num = elf_store.read2(OFFSET_ELF_HEADER_SHNUM);

        long executable_start = 0;
        long executable_end = 0;

        // parse program headers
        for (int i = 0; i < elf_program_headers_num; i++) {
            final long phdr_offset = elf_program_headers_offset + (i * SIZE_ELF_PROGRAM_HEADER);
            final Pointer phdr_pointer = elf_store.inc(phdr_offset);

            final long p_type = phdr_pointer.read4(OFFSET_PROGRAM_HEADER_TYPE);
            final long p_flags = phdr_pointer.read4(OFFSET_PROGRAM_HEADER_FLAGS);
            final long p_offset = phdr_pointer.read4(OFFSET_PROGRAM_HEADER_OFFSET);
            final long p_vaddr = phdr_pointer.read4(OFFSET_PROGRAM_HEADER_VADDR);
            final long p_filesz = phdr_pointer.read4(OFFSET_PROGRAM_HEADER_FILESZ);
            final long p_memsz = phdr_pointer.read4(OFFSET_PROGRAM_HEADER_MEMSZ);
            final long aligned_memsz = (p_memsz + 0x3FFF) & 0xFFFFC000L;

            if (p_type == ELF_PT_LOAD) {
                if ((p_flags & PF_X) == PF_X) {
                    executable_start = p_vaddr;
                    executable_end = p_vaddr + p_memsz;

                    //create shm with exec permission
                    final long exec_handle = this.libKernel.jitshm_create(0, aligned_memsz, 0x7);
                    Status.println("jitshm exec_handle: " + Long.toHexString(exec_handle));

                    // create shm alias with write permission
                    final int write_handle = this.libKernel.jitshm_alias(exec_handle, 0x3);
                    Status.println("jitshm write_handle: " + Long.toHexString(write_handle));

                    // map shadow mapping and write into it
                    Pointer result = this.mman.memoryMap(Pointer.NULL,
                            aligned_memsz,
                            new ProtectionFlag[] { ProtectionFlag.PROT_READ, ProtectionFlag.PROT_WRITE },
                            new MappingFlag[] { MappingFlag.MAP_SHARED, MappingFlag.MAP_FIXED},
                            write_handle,
                            0);
                    Status.println("mmap shadow mapping: " + Long.toHexString(result.addr()));

                    this.memcpy(Pointer.valueOf(this.shadow_mapping_addr), elf_store.inc(p_offset), p_memsz);

                    // map executable segment
                    result = this.mman.memoryMap(Pointer.valueOf(mapping_addr).inc(p_vaddr),
                            aligned_memsz,
                            new ProtectionFlag[] { ProtectionFlag.PROT_READ, ProtectionFlag.PROT_WRITE, ProtectionFlag.PROT_EXEC },
                            new MappingFlag[] { MappingFlag.MAP_SHARED, MappingFlag.MAP_FIXED},
                            write_handle,
                            0);
                    Status.println("mmap exec segment: " + Long.toHexString(result.addr()));
                } else {
                    // copy regular data segment
                    Status.println("mmap aligned_memsz: " + Long.toHexString(aligned_memsz));
                    Status.println("mmap p_vaddr: " + Long.toHexString(p_vaddr));
                    Status.println("expected mmap data segment: " + Pointer.valueOf(mapping_addr).inc(p_vaddr));
                    Pointer mmapResult = this.mman.memoryMap(Pointer.valueOf(mapping_addr).inc(p_vaddr),
                            aligned_memsz,
                            new ProtectionFlag[] { ProtectionFlag.PROT_READ, ProtectionFlag.PROT_WRITE },
                            new MappingFlag[] { MappingFlag.MAP_ANONYMOUS, MappingFlag.MAP_PRIVATE, MappingFlag.MAP_PREFAULT_READ },
                            0xFFFFFFFF,
                            0);
                    Status.println("actual mmap data segment: " + Long.toHexString(mmapResult.addr()));

                    this.memcpy(mmapResult, elf_store.inc(p_offset), p_memsz);
                }

                Status.println("memcpy finish!");
            }
        }

        // apply relocations
        for (int i = 0; i < elf_section_headers_num; i++) {
            final long shdr_offset = elf_section_headers_offset + (i * SIZE_ELF_SECTION_HEADER);
            final Pointer shdr_pointer = elf_store.inc(shdr_offset);

            final long sh_type = shdr_pointer.read4(OFFSET_SECTION_HEADER_TYPE);
            final long sh_offset = shdr_pointer.read8(OFFSET_SECTION_HEADER_OFFSET);
            final long sh_size = shdr_pointer.read8(OFFSET_SECTION_HEADER_SIZE);

            if (sh_type == SHT_RELA) {
                final long rela_table_count = sh_size / RELA_ENTSIZE;

                // Parse relocs and apply them
                for (int j = 0; j < rela_table_count; j++) {
                    final Pointer sh_pointer = elf_store.inc(sh_offset);

                    final long r_offset = sh_pointer.read8((j * RELA_ENTSIZE) + OFFSET_RELA_OFFSET);
                    final long r_info = sh_pointer.read8((j * RELA_ENTSIZE) + OFFSET_RELA_INFO);
                    final long r_addend = sh_pointer.read8((j * RELA_ENTSIZE) + OFFSET_RELA_ADDEND);

                    if ((r_info & 0xFFL) == ELF_R_AMD64_RELATIVE) {
                        long reloc_addr = this.mapping_addr + r_offset;
                        final long reloc_value = this.mapping_addr + r_addend;

                        // If the relocation falls in the executable section, we need to redirect the write to the
                        // writable shadow mapping or we'll crash
                        if (executable_start <= r_offset && r_offset < executable_end) {
                            reloc_addr = this.shadow_mapping_addr + r_offset;
                        }

                        Status.println("Writing relocation " + Long.toHexString(reloc_value) + " to " + Long.toHexString(reloc_addr));
                        Pointer.valueOf(reloc_addr).write8(reloc_value);
                    }
                }
            }
        }
    }

    private void runLoader() {
        final KernelAccessorIPv6 kernelAccessor = (KernelAccessorIPv6) KernelReadWrite.getAccessor(getClass().getClassLoader());

        final Pointer rwpipe = Pointer.calloc(8);
        final Pointer rwpair = Pointer.calloc(8);
        final Pointer args = Pointer.calloc(0x30);
        final Pointer thr_handle_addr =  Pointer.calloc(8);

        rwpipe.write4(kernelAccessor.getPipeReadFd());
        rwpipe.write4(0x4, kernelAccessor.getPipeWriteFd());

        rwpair.write4(kernelAccessor.getMasterSock());
        rwpair.write4(0x4, kernelAccessor.getVictimSock());

        final Pointer syscall_wrapper = this.libKernel.addrOf("getpid");
        Status.println("syscall_wrapper: " + Long.toHexString(syscall_wrapper.addr()));

        this.payloadout = Pointer.calloc(4);

        args.write8(0x00, syscall_wrapper.addr());
        args.write8(0x08, rwpipe.addr());
        args.write8(0x10, rwpair.addr());
        args.write8(0x18, kernelAccessor.getPipeAddr().addr());
        args.write8(0x20, kernelAccessor.getKernelDataBase());
        args.write8(0x28, this.payloadout.addr());

        // spawn elf in new thread
        final int ret = libKernel.pthread_create(thr_handle_addr, Pointer.valueOf(elf_entry_point), args);
        Status.println("thrd_create: " + Long.toHexString(ret));
    }

    private void memcpy(Pointer dest, Pointer src, long n) {
        //KernelAccessor accessor = KernelReadWrite.getAccessor(getClass().getClassLoader());

        byte[] read = src.read((int) n);
        Status.println("memcpy bytes read: " + read.length);
        /*for (int i = 0; i < read.length; i++) {
            Status.println("writing to: " + Long.toHexString(dest.inc(i).addr()));
            dest.inc(i).write1(read[i]);
            //accessor.write1(dest.inc(i).addr(), read[i]);
        }*/
        dest.write(read);
        Status.println("memcpy bytes written: " + read.length);
    }
}
