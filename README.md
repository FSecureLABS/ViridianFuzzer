# Viridian Fuzzer 

It is a kernel driver that make hypercalls, execute CPUID, read/write to MSRs from CPL0. 

### Requirements

- Requires a scheduled task, start at logon with admin privs
- Requires ViFu3.h defines for share address
- Store credentials of parent UNC in guest credential manager
- Compiled as x64 Debug
- Tested in Win10, with Hypercall Dispatch Table extracted for 1607

### Information

- Every time a fuzz attempt is ran it first writes info to fuzz_logger.txt, and registry data to VIFU_LOG.txt
- On fuzzer start, a datetime is written to fuzz_logger.txt, and checks if log has any data written to it. If so find the latest fuzz entry, and increment to next isFast/isRep, then continue fuzzing
- To start/stop autostart of fuzzer, create/delete file autoStart.txt in the log share.
  * Fuzzer won't start if it can't connect to share
- To add more fuzzing rules:
	UM: add loops to BASIC FUZZER LOOPS, or increment switch() for specific conditions i.e. different GPA mem
	KM: if mod'ing GPA mem, in case IOCTL_HYPERCALL, add new `else if`

