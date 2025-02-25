package org.ps5jb.client.payloads;

import org.ps5jb.client.utils.init.KernelReadWriteUnavailableException;
import org.ps5jb.client.utils.init.SdkInit;
import org.ps5jb.client.utils.memory.MemoryDumper;
import org.ps5jb.loader.Status;
import org.ps5jb.sdk.core.Pointer;
import org.ps5jb.sdk.core.SdkSoftwareVersionUnsupportedException;
import org.ps5jb.sdk.core.kernel.KernelPointer;
import org.ps5jb.sdk.include.sys.filedesc.FileDesc;
import org.ps5jb.sdk.include.sys.mman.ProtectionFlag;
import org.ps5jb.sdk.include.sys.proc.Process;
import org.ps5jb.sdk.include.sys.ucred.UCred;
import org.ps5jb.sdk.lib.LibKernel;

import java.io.*;
import java.lang.reflect.Field;
import java.nio.charset.Charset;
import java.util.Arrays;

public class DumpCurProcUtil {
    private static final long PROC_SIZE = 0x1400;

    private static OutputStreamWriter writer = null;

    public static void dumpCurProcToFile(File usbFile, LibKernel libKernel, SdkInit sdk) {
        try {
            writer = new OutputStreamWriter(new FileOutputStream(usbFile, false));

            Process curProc = new Process(KernelPointer.valueOf(sdk.curProcAddress));
            println("Process " + curProc.getPointer() + ":");
            MemoryDumper.dump(curProc.getPointer(), PROC_SIZE, true, writer);
            println("Ucred " + curProc.getUserCredentials().getPointer() + ":");
            MemoryDumper.dump(curProc.getUserCredentials().getPointer(), UCred.SIZE, true, writer);
            println("Fd " + curProc.getOpenFiles().getPointer() + ":");
            MemoryDumper.dump(curProc.getOpenFiles().getPointer(), FileDesc.OFFSET_FD_JDIR + 0x20, true, writer);

            println("Process Data:");
            println("  PID: " + curProc.getPid());
            println("  Title ID: " + curProc.getTitleId());
            println("  Content ID: " + curProc.getContentId());
            println("  GPU VM ID: " + curProc.getVmSpace().getGpuVmId());
            println("  Command: " + curProc.getName());
            println("  Arguments: " + curProc.getArguments());
            Process next = curProc.getNextProcess();
            if (next != null) {
                println("  Next: " + printProcess(next));
            } else {
                println("  Last in allproc");
            }
            Process prev = curProc.getPreviousProcess();
            if (prev != null) {
                println("  Previous: " + printProcess(prev));
            } else {
                println("  First in allproc");
            }
            Process groupEntry = curProc.getNextProcessInGroup();
            if (groupEntry != null) {
                println("  Next in group:");
                while (groupEntry != null) {
                    println("    " + printProcess(groupEntry));
                    groupEntry = groupEntry.getNextProcessInGroup();
                }
            }
            Process parent = curProc.getParentProcess();
            if (parent != null) {
                String indent = "  ";
                println(indent + "Parent(s):");
                while (parent != null) {
                    indent += "  ";
                    println(indent + printProcess(parent));
                    parent = parent.getParentProcess();
                }
            }
            Process sibling = curProc.getNextSiblingProcess();
            if (sibling != null) {
                println("  Next sibling(s):");
                while (sibling != null) {
                    println("    " + printProcess(sibling));
                    sibling = sibling.getNextSiblingProcess();
                }
            }
            sibling = curProc.getPreviousSiblingProcess();
            if (sibling != null) {
                println("  Prev sibling(s):");
                while (sibling != null) {
                    println("    " + printProcess(sibling));
                    sibling = sibling.getPreviousSiblingProcess();
                }
            }
            Process child = curProc.getNextChildProcess();
            if (child != null) {
                println("  Children:");
                while (child != null) {
                    println("    " + printProcess(child));
                    child = child.getNextSiblingProcess();
                }
            }
            Process reaper = curProc.getReaperProcess();
            if (reaper != null) {
                println("  Reaper: " + printProcess(reaper));
            }
            Process reapEntry = curProc.getNextReapListSiblingProcess();
            if (reapEntry != null) {
                println("  Next reap sibling(s) of the reaper:");
                while (reapEntry != null) {
                    println("    " + printProcess(reapEntry));
                    reapEntry = reapEntry.getNextReapListSiblingProcess();
                }
            }
            reapEntry = curProc.getPreviousReapListSiblingProcess();
            if (reapEntry != null) {
                println("  Prev reap sibling(s) of the reaper:");
                while (reapEntry != null) {
                    println("    " + printProcess(reapEntry));
                    reapEntry = reapEntry.getPreviousReapListSiblingProcess();
                }
            }
            Process reapChild = curProc.getNextProcessInReapList();
            if (reapChild != null) {
                println("  Reap list (of this process):");
                while (reapChild != null) {
                    println("    " + printProcess(reapChild));
                    reapChild = reapChild.getNextReapListSiblingProcess();
                }
            }

            printModuleList(libKernel);

            int curTid = libKernel.pthread_getthreadid_np();
            printNativeThreadList(curProc, curTid);

            printJavaThreadList();
        } catch (KernelReadWriteUnavailableException e) {
            println("Kernel R/W is not available, aborting");
        } catch (SdkSoftwareVersionUnsupportedException e) {
            println("Unsupported firmware version: " + e.getMessage());
        } catch (Throwable e) {
            Status.printStackTrace("Unexpected error", e);
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    private static void printJavaThreadList() throws NoSuchFieldException, IllegalAccessException {
        println("Java Threads: ");

        ThreadGroup tg = Thread.currentThread().getThreadGroup();
        while (tg.getParent() != null) {
            tg = tg.getParent();
        }
        printThreadGroup(tg, "  ");
    }

    private static void printThreadGroup(ThreadGroup tg, String indent) throws NoSuchFieldException, IllegalAccessException {
        int threadGroupCount;
        ThreadGroup[] threadGroups = new ThreadGroup[tg.activeGroupCount()];
        while ((threadGroupCount = tg.enumerate(threadGroups, false)) == threadGroups.length && threadGroupCount != 0) {
            threadGroups = new ThreadGroup[threadGroups.length * 2];
        }

        for (int i = 0; i < threadGroupCount; ++i) {
            ThreadGroup threadGroup = threadGroups[i];
            println(indent + "[G] " + threadGroup.getName() + ":");
            printThreadGroup(threadGroup, indent + "  ");
        }

        int threadCount;
        Thread[] threads = new Thread[tg.activeCount()];
        while ((threadCount = tg.enumerate(threads, false)) == threads.length && threadCount != 0) {
            threads = new Thread[threads.length * 2];
        }

        for (int i = 0; i < threadCount; ++i) {
            Thread thread = threads[i];
            Field targetField = Thread.class.getDeclaredField("target");
            targetField.setAccessible(true);
            Runnable target = (Runnable) targetField.get(thread);
            Class clazz = target != null ? target.getClass() : thread.getClass();

            println(indent + thread.getName() + " [" + clazz.getName() + "]" +
                    (thread == Thread.currentThread() ? " (this thread)" : ""));
        }
    }

    private static void printNativeThreadList(Process proc, int curTid) {
        org.ps5jb.sdk.include.sys.proc.Thread td = proc.getFirstThread();

        println("Native Threads: ");
        while (td != null) {
            println("  " + printThread(td) + (curTid == td.getTid() ? " (this thread)" : ""));
            td = td.getNextThread();
        }
    }

    private static String printThread(org.ps5jb.sdk.include.sys.proc.Thread td) {
        String name = td.getName();
        int tid = td.getTid();
        return tid + (name.length() == 0 ? "" : " " + name);
    }

    private static String printProcess(Process proc) {
        return proc.getName() + " - " + proc.getTitleId() + " - " + proc.getPathName() + " (" + proc.getPid() + ")";
    }

    private static void printModuleList(LibKernel libKernel) {
        final int maxModuleCount = 0x100;
        Pointer moduleInfo = Pointer.calloc(0x160);
        Pointer moduleList = Pointer.calloc(4L * maxModuleCount);
        Pointer moduleCountPtr = Pointer.calloc(8);
        try {
            int res;
            if ((res = libKernel.sceKernelGetModuleList(moduleList, maxModuleCount, moduleCountPtr)) == 0) {
                final long moduleCount = moduleCountPtr.read8();
                final Integer maxName = new Integer(256);
                println("Modules (" + moduleCount + "):");
                for (long i = 0; i < moduleCount; ++ i) {
                    int moduleHandle = moduleList.read4(i * 4);
                    println("  Handle: 0x" + Integer.toHexString(moduleHandle));

                    moduleInfo.write8(0x160);
                    if ((res = libKernel.sceKernelGetModuleInfo(moduleHandle, moduleInfo)) == 0) {
                        int segmentCount = moduleInfo.read4(0x148);
                        String name = moduleInfo.readString(0x08, maxName, Charset.defaultCharset().name());
                        println("  Name: " + name);
                        println("  Segments (" + segmentCount + "):");
                        for (int j = 0; j < segmentCount; ++j) {
                            long start = moduleInfo.read8(0x108 + 0x10L * j);
                            long size = moduleInfo.read4(0x108 + 0x10L * j + 0x08);
                            println("    Start: 0x" + Long.toHexString(start));
                            println("    End: 0x" + Long.toHexString(start + size) + " (size: 0x" + Long.toHexString(size) + ")");
                            println("    Protection: " + Arrays.asList(ProtectionFlag.valueOf(moduleInfo.read4(0x108 + 0x10L * j + 0x0C))));
                        }
                    } else {
                        println("    [ERROR] Unable to obtain the module info: 0x" + Integer.toHexString(res));
                    }
                }
            } else {
                println("Unable to obtain the process module list: 0x" + Integer.toHexString(res));
            }
        } finally {
            moduleCountPtr.free();
            moduleList.free();
            moduleInfo.free();
        }
    }

    private static void println(String line) {
        if (writer == null) {
            throw new IllegalStateException("no writer present");
        }

        try {
            writer.write(line + "\n");
        } catch (IOException ex) {
            Status.println("print-error: " + line);
        }
    }
}
