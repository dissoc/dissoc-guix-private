(define-module (dissoc nongnu packages linux)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages algebra)
  #:use-module (gnu packages bison)
  #:use-module (gnu packages cpio)
  #:use-module (gnu packages elf)
  #:use-module (gnu packages flex)
  #:use-module (gnu packages linux)
  #:use-module (gnu packages llvm)
  #:use-module (gnu packages multiprecision)
  #:use-module (gnu packages perl)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages tls)
  #:use-module (guix build-system gnu)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (ice-9 match)

  )


;; Many of the packages in this module are custom linux
;; builds to be used for testing bpf. You probably do not
;; want or need to use them.

(define config->string (@@ (gnu packages linux) config->string))

(define kernel-config (@@ (gnu packages linux) kernel-config))

(define %bpf-extra-linux-options
  `(;; Needed for probes
    ("CONFIG_UPROBE_EVENTS" . #t)
    ("CONFIG_KPROBE_EVENTS" . #t)
    ;; kheaders module also helpful for tracing
    ("CONFIG_IKHEADERS" . #t)
    ("CONFIG_BPF" . #t)
    ("CONFIG_BPF_SYSCALL" . #t)
    ("CONFIG_BPF_JIT_ALWAYS_ON" . #t)
    ;; optional, for tc filters
    ("CONFIG_NET_CLS_BPF" . m)
    ;; optional, for tc actions
    ("CONFIG_NET_ACT_BPF" . m)
    ("CONFIG_BPF_JIT" . #t)
    ;; for Linux kernel versions 4.7 and later
    ("CONFIG_HAVE_EBPF_JIT" . #t)
    ;; optional, for kprobes
    ("CONFIG_BPF_EVENTS" . #t)
    ;;    ("INIT_STACK_NONE" . #t)
    ;; kheaders module
    ("CONFIG_IKHEADERS" . #t)
    ;; default
    ("CONFIG_IKCONFIG" . #t)
    ("CONFIG_IKCONFIG_PROC" . #t)
    ;; Some very mild hardening.
    ("CONFIG_SECURITY_DMESG_RESTRICT" . #t)
    ;; All kernels should have NAMESPACES options enabled
    ("CONFIG_NAMESPACES" . #t)
    ("CONFIG_UTS_NS" . #t)
    ("CONFIG_IPC_NS" . #t)
    ("CONFIG_USER_NS" . #t)
    ("CONFIG_PID_NS" . #t)
    ("CONFIG_NET_NS" . #t)
    ;; Various options needed for elogind service:
    ;; https://issues.guix.gnu.org/43078
    ("CONFIG_CGROUP_FREEZER" . #t)
    ("CONFIG_BLK_CGROUP" . #t)
    ("CONFIG_CGROUP_WRITEBACK" . #t)
    ("CONFIG_CGROUP_SCHED" . #t)
    ("CONFIG_CGROUP_PIDS" . #t)
    ("CONFIG_CGROUP_FREEZER" . #t)
    ("CONFIG_CGROUP_DEVICE" . #t)
    ("CONFIG_CGROUP_CPUACCT" . #t)
    ("CONFIG_CGROUP_PERF" . #t)
    ("CONFIG_SOCK_CGROUP_DATA" . #t)
    ("CONFIG_BLK_CGROUP_IOCOST" . #t)
    ("CONFIG_CGROUP_NET_PRIO" . #t)
    ("CONFIG_CGROUP_NET_CLASSID" . #t)
    ("CONFIG_MEMCG" . #t)
    ("CONFIG_MEMCG_SWAP" . #t)
    ("CONFIG_MEMCG_KMEM" . #t)
    ("CONFIG_CPUSETS" . #t)
    ("CONFIG_PROC_PID_CPUSET" . #t)
    ;; Allow disk encryption by default
    ("CONFIG_DM_CRYPT" . m)
    ;; Support zram on all kernel configs
    ("CONFIG_ZSWAP" . #t)
    ("CONFIG_ZSMALLOC" . #t)
    ("CONFIG_ZRAM" . m)
    ;; Accessibility support.
    ("CONFIG_ACCESSIBILITY" . #t)
    ("CONFIG_A11Y_BRAILLE_CONSOLE" . #t)
    ("CONFIG_SPEAKUP" . m)
    ("CONFIG_SPEAKUP_SYNTH_SOFT" . m)
    ;; Modules required for initrd:
    ("CONFIG_NET_9P" . m)
    ("CONFIG_NET_9P_VIRTIO" . m)
    ("CONFIG_VIRTIO_BLK" . m)
    ("CONFIG_VIRTIO_NET" . m)
    ("CONFIG_VIRTIO_PCI" . m)
    ("CONFIG_VIRTIO_BALLOON" . m)
    ("CONFIG_VIRTIO_MMIO" . m)
    ("CONFIG_FUSE_FS" . m)
    ("CONFIG_CIFS" . m)
    ("CONFIG_9P_FS" . m)))

(define-public linux-bpf-sched-ext
  (package
   (name "linux-bpf-sched-ext")
   (version "6.7.1")
   (source (origin
            (method url-fetch)
            (patches
             (list "patches/linux-v6.7.1-scx1.patch"))
            (uri (string-append "mirror://kernel.org"
                                "/linux/kernel/v" "6" ".x/"
                                "linux-" "6.7.1" ".tar.xz"))
            (sha256 (base32 "1hv8mma3i6zhjix5k2g12jmajqy29c1xjfjkllmj18l6irbgmkqy"))))
   (build-system gnu-build-system)
   (arguments
    (list
     #:modules '((guix build gnu-build-system)
                 (guix build utils)
                 (srfi srfi-1)
                 (srfi srfi-26)
                 (ice-9 ftw)
                 (ice-9 match))
     #:tests? #f
     #:phases
     #~(modify-phases
        %standard-phases
        (add-after 'unpack 'patch-/bin/pwd
                   (lambda _
                     (substitute* (find-files
                                   "." "^Makefile(\\.include)?$")
                                  (("/bin/pwd") "pwd"))))
        (add-before 'configure 'set-environment
                    (lambda* (#:key target #:allow-other-keys)
                      ;; Avoid introducing timestamps.
                      (setenv "KCONFIG_NOTIMESTAMP" "1")
                      (setenv "KBUILD_BUILD_TIMESTAMP" (getenv "SOURCE_DATE_EPOCH"))

                      ;; Other variables useful for reproducibility.
                      (setenv "KBUILD_BUILD_USER" "guix")
                      (setenv "KBUILD_BUILD_HOST" "guix")

                      ;; Set ARCH and CROSS_COMPILE.
                      (let ((arch "x86_64"))
                        (setenv "ARCH" arch)
                        (format #t "`ARCH' set to `~a'~%" (getenv "ARCH"))
                        (when target
                          (setenv "CROSS_COMPILE" (string-append target "-"))
                          (format #t "`CROSS_COMPILE' set to `~a'~%"
                                  (getenv "CROSS_COMPILE"))))

                      ;; Allow EXTRAVERSION to be set via the environment.
                      (substitute* "Makefile"
                                   (("^ *EXTRAVERSION[[:blank:]]*=")
                                    "EXTRAVERSION ?="))
                      (setenv "EXTRAVERSION"
                              #$(and #f
                                     (string-append "-" #f)))))
        (replace 'configure
                 (lambda _
                   (let ((config
                          #$(match (let ((arch "x86_64")
                                         (configuration-file kernel-config))
                                     (and configuration-file arch
                                          (configuration-file
                                           arch
                                           #:variant (version-major+minor version))))
                              (#f            ;no config for this platform
                               #f)
                              ((? file-like? config)
                               config))))
                     ;; Use a custom kernel configuration file or a default
                     ;; configuration file.
                     (if config
                         (begin
                           (copy-file config ".config")
                           (chmod ".config" #o666))
                         (invoke "make" "LLVM=1" "defconfig"))
                     ;; Appending works even when the option wasn't in the file.
                     ;; The last one prevails if duplicated.
                     (let ((port (open-file ".config" "a"))
                           (extra-configuration #$(config->string %bpf-extra-linux-options)))
                       (display extra-configuration port)
                       (close-port port))
                     (invoke "make" "LLVM=1" "oldconfig"))))
        (replace 'build
                 (lambda* (#:key inputs parallel-build? #:allow-other-keys)
                   (let ((clang-path (string-append "PATH="
                                                    (assoc-ref inputs "clang-toolchain")
                                                    "/bin/:" (getenv "PATH"))))
                     (invoke "make" "LLVM=1" "LLVM_IAS=1"
                             "-j" (if parallel-build?
                                      (number->string (parallel-job-count))
                                      "1")))))
        (replace 'install
                 (lambda _
                   (let ((moddir (string-append #$output "/lib/modules"))
                         (dtbdir (string-append #$output "/lib/dtbs")))
                     ;; Install kernel image, kernel configuration and link map.
                     (for-each (lambda (file) (install-file file #$output))
                               (find-files "." "^(\\.config|bzImage|zImage|Image\
|vmlinuz|System\\.map|Module\\.symvers)$"))
                     ;; Install device tree files
                     (unless (null? (find-files "." "\\.dtb$"))
                       (mkdir-p dtbdir)
                       (invoke "make"
                               "LLVM=1"
                               "LLVM_IAS=1"
                               (string-append "INSTALL_DTBS_PATH=" dtbdir)
                               "dtbs_install"))
                     ;; Install kernel modules
                     (mkdir-p moddir)
                     (invoke "make"
                             ;; Disable depmod because the Guix system's module
                             ;; directory is an union of potentially multiple
                             ;; packages.  It is not possible to use depmod to
                             ;; usefully calculate a dependency graph while
                             ;; building only one of them.
                             "DEPMOD=true"
                             (string-append "MODULE_DIR=" moddir)
                             (string-append "INSTALL_PATH=" #$output)
                             (string-append "INSTALL_MOD_PATH=" #$output)
                             "INSTALL_MOD_STRIP=1"
                             "LLVM=1"
                             "LLVM_IAS=1"
                             "modules_install")
                     (let* ((versions (filter (lambda (name)
                                                (not (string-prefix? "." name)))
                                              (scandir moddir)))
                            (version (match versions
                                       ((x) x))))
                       ;; There are symlinks to the build and source directory.
                       ;; Both will point to target /tmp/guix-build* and thus not
                       ;; be useful in a profile.  Delete the symlinks.
                       (false-if-file-not-found
                        (delete-file
                         (string-append moddir "/" version "/build")))
                       (false-if-file-not-found
                        (delete-file
                         (string-append moddir "/" version "/source"))))))))))
   (inputs (list cpio))
   (native-inputs
    (list perl
          bc
          cpio
          clang-toolchain
          lld
          openssl
          elfutils                  ;needed to enable CONFIG_STACK_VALIDATION
          flex
          bison
          util-linux                ;needed for hexdump
          ;; These are needed to compile the GCC plugins.
          gmp
          mpfr
          mpc))
   (home-page "https://www.gnu.org/software/linux-libre/")
   (synopsis "100% free redistribution of a cleaned Linux kernel")
   (description "GNU Linux-Libre is a free (as in freedom) variant of the
Linux kernel.  It has been modified to remove all non-free binary blobs.")
   (license license:gpl2)
   (properties '((max-silent-time . 10800)))))
linux-bpf-sched-ext
