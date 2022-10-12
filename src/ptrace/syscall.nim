{.pragma: s,
 importc,
 header: "sys/syscall.h"
.}

let
  SYS_llseek* {.s, importc: "SYS__llseek".}: cint
  SYS_newselect* {.s, importc: "SYS__newselect".}: cint
  SYS_sysctl* {.s, importc: "SYS_sysctl".}: cint
  SYS_access* {.s.}: cint
  SYS_acct* {.s.}: cint
  SYS_add_key* {.s.}: cint
  SYS_adjtimex* {.s.}: cint
  SYS_afs_syscall* {.s.}: cint
  SYS_alarm* {.s.}: cint
  SYS_bdflush* {.s.}: cint
  SYS_bpf* {.s.}: cint
  SYS_break* {.s.}: cint
  SYS_brk* {.s.}: cint
  SYS_capget* {.s.}: cint
  SYS_capset* {.s.}: cint
  SYS_chdir* {.s.}: cint
  SYS_chmod* {.s.}: cint
  SYS_chown* {.s.}: cint
  SYS_chown32* {.s.}: cint
  SYS_chroot* {.s.}: cint
  SYS_clock_adjtime* {.s.}: cint
  SYS_clock_getres* {.s.}: cint
  SYS_clock_gettime* {.s.}: cint
  SYS_clock_nanosleep* {.s.}: cint
  SYS_clock_settime* {.s.}: cint
  SYS_clone* {.s.}: cint
  SYS_close* {.s.}: cint
  SYS_creat* {.s.}: cint
  SYS_create_module* {.s.}: cint
  SYS_delete_module* {.s.}: cint
  SYS_dup* {.s.}: cint
  SYS_dup2* {.s.}: cint
  SYS_dup3* {.s.}: cint
  SYS_epoll_create* {.s.}: cint
  SYS_epoll_create1* {.s.}: cint
  SYS_epoll_ctl* {.s.}: cint
  SYS_epoll_pwait* {.s.}: cint
  SYS_epoll_wait* {.s.}: cint
  SYS_eventfd* {.s.}: cint
  SYS_eventfd2* {.s.}: cint
  SYS_execve* {.s.}: cint
  SYS_execveat* {.s.}: cint
  SYS_exit* {.s.}: cint
  SYS_exit_group* {.s.}: cint
  SYS_faccessat* {.s.}: cint
  SYS_fadvise64* {.s.}: cint
  SYS_fadvise64_64* {.s.}: cint
  SYS_fallocate* {.s.}: cint
  SYS_fanotify_init* {.s.}: cint
  SYS_fanotify_mark* {.s.}: cint
  SYS_fchdir* {.s.}: cint
  SYS_fchmod* {.s.}: cint
  SYS_fchmodat* {.s.}: cint
  SYS_fchown* {.s.}: cint
  SYS_fchown32* {.s.}: cint
  SYS_fchownat* {.s.}: cint
  SYS_fcntl* {.s.}: cint
  SYS_fcntl64* {.s.}: cint
  SYS_fdatasync* {.s.}: cint
  SYS_fgetxattr* {.s.}: cint
  SYS_finit_module* {.s.}: cint
  SYS_flistxattr* {.s.}: cint
  SYS_flock* {.s.}: cint
  SYS_fork* {.s.}: cint
  SYS_fremovexattr* {.s.}: cint
  SYS_fsetxattr* {.s.}: cint
  SYS_fstat* {.s.}: cint
  SYS_fstat64* {.s.}: cint
  SYS_fstatat64* {.s.}: cint
  SYS_fstatfs* {.s.}: cint
  SYS_fstatfs64* {.s.}: cint
  SYS_fsync* {.s.}: cint
  SYS_ftime* {.s.}: cint
  SYS_ftruncate* {.s.}: cint
  SYS_ftruncate64* {.s.}: cint
  SYS_futex* {.s.}: cint
  SYS_futimesat* {.s.}: cint
  SYS_get_kernel_syms* {.s.}: cint
  SYS_get_mempolicy* {.s.}: cint
  SYS_get_robust_list* {.s.}: cint
  SYS_get_thread_area* {.s.}: cint
  SYS_getcpu* {.s.}: cint
  SYS_getcwd* {.s.}: cint
  SYS_getdents* {.s.}: cint
  SYS_getdents64* {.s.}: cint
  SYS_getegid* {.s.}: cint
  SYS_getegid32* {.s.}: cint
  SYS_geteuid* {.s.}: cint
  SYS_geteuid32* {.s.}: cint
  SYS_getgid* {.s.}: cint
  SYS_getgid32* {.s.}: cint
  SYS_getgroups* {.s.}: cint
  SYS_getgroups32* {.s.}: cint
  SYS_getitimer* {.s.}: cint
  SYS_getpgid* {.s.}: cint
  SYS_getpgrp* {.s.}: cint
  SYS_getpid* {.s.}: cint
  SYS_getpmsg* {.s.}: cint
  SYS_getppid* {.s.}: cint
  SYS_getpriority* {.s.}: cint
  SYS_getrandom* {.s.}: cint
  SYS_getresgid* {.s.}: cint
  SYS_getresgid32* {.s.}: cint
  SYS_getresuid* {.s.}: cint
  SYS_getresuid32* {.s.}: cint
  SYS_getrlimit* {.s.}: cint
  SYS_getrusage* {.s.}: cint
  SYS_getsid* {.s.}: cint
  SYS_gettid* {.s.}: cint
  SYS_gettimeofday* {.s.}: cint
  SYS_getuid* {.s.}: cint
  SYS_getuid32* {.s.}: cint
  SYS_getxattr* {.s.}: cint
  SYS_gtty* {.s.}: cint
  SYS_idle* {.s.}: cint
  SYS_init_module* {.s.}: cint
  SYS_inotify_add_watch* {.s.}: cint
  SYS_inotify_init* {.s.}: cint
  SYS_inotify_init1* {.s.}: cint
  SYS_inotify_rm_watch* {.s.}: cint
  SYS_io_cancel* {.s.}: cint
  SYS_io_destroy* {.s.}: cint
  SYS_io_getevents* {.s.}: cint
  SYS_io_setup* {.s.}: cint
  SYS_io_submit* {.s.}: cint
  SYS_ioctl* {.s.}: cint
  SYS_ioperm* {.s.}: cint
  SYS_iopl* {.s.}: cint
  SYS_ioprio_get* {.s.}: cint
  SYS_ioprio_set* {.s.}: cint
  SYS_ipc* {.s.}: cint
  SYS_kcmp* {.s.}: cint
  SYS_kexec_load* {.s.}: cint
  SYS_keyctl* {.s.}: cint
  SYS_kill* {.s.}: cint
  SYS_lchown* {.s.}: cint
  SYS_lchown32* {.s.}: cint
  SYS_lgetxattr* {.s.}: cint
  SYS_link* {.s.}: cint
  SYS_linkat* {.s.}: cint
  SYS_listxattr* {.s.}: cint
  SYS_llistxattr* {.s.}: cint
  SYS_lock* {.s.}: cint
  SYS_lookup_dcookie* {.s.}: cint
  SYS_lremovexattr* {.s.}: cint
  SYS_lseek* {.s.}: cint
  SYS_lsetxattr* {.s.}: cint
  SYS_lstat* {.s.}: cint
  SYS_lstat64* {.s.}: cint
  SYS_madvise* {.s.}: cint
  SYS_mbind* {.s.}: cint
  SYS_memfd_create* {.s.}: cint
  SYS_migrate_pages* {.s.}: cint
  SYS_mincore* {.s.}: cint
  SYS_mkdir* {.s.}: cint
  SYS_mkdirat* {.s.}: cint
  SYS_mknod* {.s.}: cint
  SYS_mknodat* {.s.}: cint
  SYS_mlock* {.s.}: cint
  SYS_mlockall* {.s.}: cint
  SYS_mmap* {.s.}: cint
  SYS_mmap2* {.s.}: cint
  SYS_modify_ldt* {.s.}: cint
  SYS_mount* {.s.}: cint
  SYS_move_pages* {.s.}: cint
  SYS_mprotect* {.s.}: cint
  SYS_mpx* {.s.}: cint
  SYS_mq_getsetattr* {.s.}: cint
  SYS_mq_notify* {.s.}: cint
  SYS_mq_open* {.s.}: cint
  SYS_mq_timedreceive* {.s.}: cint
  SYS_mq_timedsend* {.s.}: cint
  SYS_mq_unlink* {.s.}: cint
  SYS_mremap* {.s.}: cint
  SYS_msync* {.s.}: cint
  SYS_munlock* {.s.}: cint
  SYS_munlockall* {.s.}: cint
  SYS_munmap* {.s.}: cint
  SYS_name_to_handle_at* {.s.}: cint
  SYS_nanosleep* {.s.}: cint
  SYS_nfsservctl* {.s.}: cint
  SYS_nice* {.s.}: cint
  SYS_oldfstat* {.s.}: cint
  SYS_oldlstat* {.s.}: cint
  SYS_oldolduname* {.s.}: cint
  SYS_oldstat* {.s.}: cint
  SYS_olduname* {.s.}: cint
  SYS_open* {.s.}: cint
  SYS_open_by_handle_at* {.s.}: cint
  SYS_openat* {.s.}: cint
  SYS_pause* {.s.}: cint
  SYS_perf_event_open* {.s.}: cint
  SYS_personality* {.s.}: cint
  SYS_pipe* {.s.}: cint
  SYS_pipe2* {.s.}: cint
  SYS_pivot_root* {.s.}: cint
  SYS_poll* {.s.}: cint
  SYS_ppoll* {.s.}: cint
  SYS_prctl* {.s.}: cint
  SYS_pread64* {.s.}: cint
  SYS_preadv* {.s.}: cint
  SYS_prlimit64* {.s.}: cint
  SYS_process_vm_readv* {.s.}: cint
  SYS_process_vm_writev* {.s.}: cint
  SYS_prof* {.s.}: cint
  SYS_profil* {.s.}: cint
  SYS_pselect6* {.s.}: cint
  SYS_ptrace* {.s.}: cint
  SYS_putpmsg* {.s.}: cint
  SYS_pwrite64* {.s.}: cint
  SYS_pwritev* {.s.}: cint
  SYS_query_module* {.s.}: cint
  SYS_quotactl* {.s.}: cint
  SYS_read* {.s.}: cint
  SYS_readahead* {.s.}: cint
  SYS_readdir* {.s.}: cint
  SYS_readlink* {.s.}: cint
  SYS_readlinkat* {.s.}: cint
  SYS_readv* {.s.}: cint
  SYS_reboot* {.s.}: cint
  SYS_recvmmsg* {.s.}: cint
  SYS_remap_file_pages* {.s.}: cint
  SYS_removexattr* {.s.}: cint
  SYS_rename* {.s.}: cint
  SYS_renameat* {.s.}: cint
  SYS_renameat2* {.s.}: cint
  SYS_request_key* {.s.}: cint
  SYS_restart_syscall* {.s.}: cint
  SYS_rmdir* {.s.}: cint
  SYS_rt_sigaction* {.s.}: cint
  SYS_rt_sigpending* {.s.}: cint
  SYS_rt_sigprocmask* {.s.}: cint
  SYS_rt_sigqueueinfo* {.s.}: cint
  SYS_rt_sigreturn* {.s.}: cint
  SYS_rt_sigsuspend* {.s.}: cint
  SYS_rt_sigtimedwait* {.s.}: cint
  SYS_rt_tgsigqueueinfo* {.s.}: cint
  SYS_sched_get_priority_max* {.s.}: cint
  SYS_sched_get_priority_min* {.s.}: cint
  SYS_sched_getaffinity* {.s.}: cint
  SYS_sched_getattr* {.s.}: cint
  SYS_sched_getparam* {.s.}: cint
  SYS_sched_getscheduler* {.s.}: cint
  SYS_sched_rr_get_interval* {.s.}: cint
  SYS_sched_setaffinity* {.s.}: cint
  SYS_sched_setattr* {.s.}: cint
  SYS_sched_setparam* {.s.}: cint
  SYS_sched_setscheduler* {.s.}: cint
  SYS_sched_yield* {.s.}: cint
  SYS_seccomp* {.s.}: cint
  SYS_select* {.s.}: cint
  SYS_sendfile* {.s.}: cint
  SYS_sendfile64* {.s.}: cint
  SYS_sendmmsg* {.s.}: cint
  SYS_set_mempolicy* {.s.}: cint
  SYS_set_robust_list* {.s.}: cint
  SYS_set_thread_area* {.s.}: cint
  SYS_set_tid_address* {.s.}: cint
  SYS_setdomainname* {.s.}: cint
  SYS_setfsgid* {.s.}: cint
  SYS_setfsgid32* {.s.}: cint
  SYS_setfsuid* {.s.}: cint
  SYS_setfsuid32* {.s.}: cint
  SYS_setgid* {.s.}: cint
  SYS_setgid32* {.s.}: cint
  SYS_setgroups* {.s.}: cint
  SYS_setgroups32* {.s.}: cint
  SYS_sethostname* {.s.}: cint
  SYS_setitimer* {.s.}: cint
  SYS_setns* {.s.}: cint
  SYS_setpgid* {.s.}: cint
  SYS_setpriority* {.s.}: cint
  SYS_setregid* {.s.}: cint
  SYS_setregid32* {.s.}: cint
  SYS_setresgid* {.s.}: cint
  SYS_setresgid32* {.s.}: cint
  SYS_setresuid* {.s.}: cint
  SYS_setresuid32* {.s.}: cint
  SYS_setreuid* {.s.}: cint
  SYS_setreuid32* {.s.}: cint
  SYS_setrlimit* {.s.}: cint
  SYS_setsid* {.s.}: cint
  SYS_settimeofday* {.s.}: cint
  SYS_setuid* {.s.}: cint
  SYS_setuid32* {.s.}: cint
  SYS_setxattr* {.s.}: cint
  SYS_sgetmask* {.s.}: cint
  SYS_sigaction* {.s.}: cint
  SYS_sigaltstack* {.s.}: cint
  SYS_signal* {.s.}: cint
  SYS_signalfd* {.s.}: cint
  SYS_signalfd4* {.s.}: cint
  SYS_sigpending* {.s.}: cint
  SYS_sigprocmask* {.s.}: cint
  SYS_sigreturn* {.s.}: cint
  SYS_sigsuspend* {.s.}: cint
  SYS_socketcall* {.s.}: cint
  SYS_splice* {.s.}: cint
  SYS_ssetmask* {.s.}: cint
  SYS_stat* {.s.}: cint
  SYS_stat64* {.s.}: cint
  SYS_statfs* {.s.}: cint
  SYS_statfs64* {.s.}: cint
  SYS_stime* {.s.}: cint
  SYS_stty* {.s.}: cint
  SYS_swapoff* {.s.}: cint
  SYS_swapon* {.s.}: cint
  SYS_symlink* {.s.}: cint
  SYS_symlinkat* {.s.}: cint
  SYS_sync* {.s.}: cint
  SYS_sync_file_range* {.s.}: cint
  SYS_syncfs* {.s.}: cint
  SYS_sysfs* {.s.}: cint
  SYS_sysinfo* {.s.}: cint
  SYS_syslog* {.s.}: cint
  SYS_tee* {.s.}: cint
  SYS_tgkill* {.s.}: cint
  SYS_time* {.s.}: cint
  SYS_timer_create* {.s.}: cint
  SYS_timer_delete* {.s.}: cint
  SYS_timer_getoverrun* {.s.}: cint
  SYS_timer_gettime* {.s.}: cint
  SYS_timer_settime* {.s.}: cint
  SYS_timerfd_create* {.s.}: cint
  SYS_timerfd_gettime* {.s.}: cint
  SYS_timerfd_settime* {.s.}: cint
  SYS_times* {.s.}: cint
  SYS_tkill* {.s.}: cint
  SYS_truncate* {.s.}: cint
  SYS_truncate64* {.s.}: cint
  SYS_ugetrlimit* {.s.}: cint
  SYS_ulimit* {.s.}: cint
  SYS_umask* {.s.}: cint
  SYS_umount* {.s.}: cint
  SYS_umount2* {.s.}: cint
  SYS_uname* {.s.}: cint
  SYS_unlink* {.s.}: cint
  SYS_unlinkat* {.s.}: cint
  SYS_unshare* {.s.}: cint
  SYS_uselib* {.s.}: cint
  SYS_ustat* {.s.}: cint
  SYS_utime* {.s.}: cint
  SYS_utimensat* {.s.}: cint
  SYS_utimes* {.s.}: cint
  SYS_vfork* {.s.}: cint
  SYS_vhangup* {.s.}: cint
  SYS_vm86* {.s.}: cint
  SYS_vm86old* {.s.}: cint
  SYS_vmsplice* {.s.}: cint
  SYS_vserver* {.s.}: cint
  SYS_wait4* {.s.}: cint
  SYS_waitid* {.s.}: cint
  SYS_waitpid* {.s.}: cint
  SYS_write* {.s.}: cint
  SYS_writev* {.s.}: cint