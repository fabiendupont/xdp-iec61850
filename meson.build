# SPDX-License-Identifier: BSD-2-Clause
# xdp-iec61850 — IEC 61850 GOOSE + SV + MMS on XDP

project('xdp-iec61850', 'c',
    version: '0.1.0',
    license: 'BSD-2-Clause',
    default_options: [
        'c_std=c11',
        'warning_level=3',
        'buildtype=debug',
        'werror=true',
    ],
    meson_version: '>=0.56.0'
)

cc = meson.get_compiler('c')

# Common warning flags
warning_flags = [
    '-Wconversion',
    '-Wshadow',
    '-Wstrict-prototypes',
    '-Wmissing-prototypes',
]

add_project_arguments(cc.get_supported_arguments(warning_flags), language: 'c')

# POSIX and GNU feature-test macros — defined globally so source files do not
# use reserved identifiers (_POSIX_C_SOURCE etc.) directly, which clang-tidy
# cert-dcl37-c flags as violations.
add_project_arguments(['-D_POSIX_C_SOURCE=200809L', '-D_DEFAULT_SOURCE'], language: 'c')

# Security compile flag (must be before build targets)
if get_option('enable_security')
    add_project_arguments('-DIEC61850_SECURITY_ENABLED', language: 'c')
endif

# Include directories
# include/iec61850/ is the primary include path so that
# includes like "containers/fixed_string.h" resolve correctly
inc_dirs = include_directories('include/iec61850')

# Required dependencies
thread_dep = dependency('threads')

# Optional: xdp-graph-lib (required for XSK transport, optional for unit tests)
xgl_dep = dependency('xdp-graph-lib', required: false,
                      fallback: ['xdp-graph-lib', 'xgl_dep'])
libbpf_dep = dependency('libbpf', version: '>=1.0', required: false)
libelf_dep = dependency('libelf', required: false)

# Optional dependencies
libxml2_dep = dependency('libxml-2.0', required: get_option('enable_mms'))
openssl_dep = dependency('openssl', required: get_option('enable_security'))
libyaml_dep = dependency('yaml-0.1', required: false)

# Core library sources
core_sources = files(
    # Phase 1: containers, logging
    'src/containers/fixed_string.c',
    'src/containers/fixed_array.c',
    'src/containers/ring_buffer.c',
    'src/logging/logger.c',
    # Phase 2: BER codec
    'src/asn1/goose_ber.c',
    'src/asn1/goose_ber_decode.c',
    'src/asn1/sv_ber.c',
    # Phase 3: GOOSE protocol
    'src/goose/goose_publisher.c',
    'src/goose/goose_subscriber.c',
    'src/goose/goose_retransmission.c',
    # Phase 5: Sampled Values protocol
    'src/sv/sv_publisher.c',
    'src/sv/sv_subscriber.c',
    # Phase 7: IED data model (always built)
    'src/ied/ied_data_model.c',
    'src/ied/ied_types.c',
    # Phase 7: Config + Monitoring (always built)
    'src/config/config_manager.c',
    'src/monitoring/system_monitor.c',
    'src/monitoring/latency_stats.c',
)

core_deps = [thread_dep]

# Transport: XSK requires xdp-graph-lib, raw sockets always available
transport_sources = files(
    'src/transport/packet_io_raw.c',
    'src/transport/eth_frame.c',
    'src/transport/ptp_clock.c',
)

if xgl_dep.found()
    transport_sources += files(
        'src/transport/packet_io_xsk.c',
        'src/iec61850_graph.c',
    )
    core_deps += [xgl_dep]
    if libbpf_dep.found()
        core_deps += [libbpf_dep]
    endif
    if libelf_dep.found()
        core_deps += [libelf_dep]
    endif
endif

# Optional: MMS (requires libxml2 for SCL parser)
# mms_ber.c has relaxed conversion warnings (large codec, 4900+ lines)
mms_sources = []
mms_lib = []
if get_option('enable_mms')
    mms_ber_lib = static_library('mms_ber',
        'src/asn1/mms_ber.c',
        include_directories: inc_dirs,
        dependencies: [thread_dep],
        c_args: ['-Wno-conversion', '-Wno-sign-conversion', '-Wno-shadow',
                 '-Wno-unused-function'],
    )
    mms_lib += [mms_ber_lib]
    core_sources += files(
        'src/mms/mms_data_store.c',
        'src/mms/mms_server.c',
        'src/mms/mms_client.c',
        'src/mms/mms_client_core.c',
        'src/mms/mms_client_rcb.c',
        'src/mms/mms_report.c',
        'src/mms/mms_control.c',
        'src/mms/mms_file_service.c',
        'src/mms/mms_journal.c',
        'src/transport/tcp_socket.c',
        'src/transport/iso_stack.c',
        'src/scl/scl_parser.c',
        'src/scl/scl_ied_builder.c',
        'src/scl/scl_rcb_config.c',
        'src/mms/mms_variable_binding.c',
    )
    core_deps += [libxml2_dep]
endif

# Optional: Security (requires OpenSSL)
if get_option('enable_security')
    core_sources += files(
        'src/security/key_manager.c',
        'src/security/hmac_verify.c',
        'src/security/cert_manager.c',
    )
    core_deps += [openssl_dep]
endif

# Optional: YAML config parser
if libyaml_dep.found()
    core_sources += files('src/config/yaml_parser.c')
    core_deps += [libyaml_dep]
endif

# Optional: HSR/PRP redundancy (requires xdp-hsr-prp)
hsr_prp_dep = dependency('xdp-hsr-prp', required: get_option('enable_hsr_prp'))
if get_option('enable_hsr_prp') and hsr_prp_dep.found()
    add_project_arguments('-DIEC61850_HSR_PRP_ENABLED', language: 'c')
    core_deps += [hsr_prp_dep]
endif
core_sources += files('src/redundancy/hsr_prp_wrapper.c')

# BPF programs (compiled with clang targeting BPF)
clang = find_program('clang', required: false)
if clang.found() and libbpf_dep.found() and xgl_dep.found()
    bpf_inc = []
    # Find libbpf headers
    libbpf_inc = run_command('pkg-config', '--cflags-only-I', 'libbpf',
                              check: false)
    if libbpf_inc.returncode() == 0
        bpf_inc += libbpf_inc.stdout().strip().split()
    endif

    # xdp-graph-lib and ebpf-graph-lib include paths for BPF custom_target
    # (custom_target does not honour dependency()/include_directories() objects)
    xgl_sub = subproject('xdp-graph-lib')
    xgl_inc_dir = xgl_sub.get_variable('xgl_inc_dir')
    egl_sub = subproject('ebpf-graph-lib')
    egl_inc_dir = egl_sub.get_variable('egl_inc_dir')

    bpf_cflags = ['-target', 'bpf', '-O2', '-g', '-Wall', '-Wextra',
                  '-D__TARGET_ARCH_x86', '-D__BPF__',
                  '-I' + meson.current_source_dir() / 'include',
                  '-I' + meson.current_source_dir() / 'src/bpf',
                  '-I' + xgl_inc_dir,
                  '-I' + egl_inc_dir]
    bpf_cflags += bpf_inc

    bpf_nodes = ['node_goose_filter', 'node_goose_parse',
                 'node_sv_filter', 'node_sv_parse']
    foreach node : bpf_nodes
        bpf_target = custom_target(node + '.bpf.o',
            input: 'src/bpf/' + node + '.bpf.c',
            output: node + '.bpf.o',
            command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'],
            install: true,
            install_dir: get_option('libdir') / 'bpf' / 'iec61850')
    endforeach
endif

# Build the core library
iec61850_lib = static_library('iec61850',
    core_sources + transport_sources,
    include_directories: inc_dirs,
    dependencies: core_deps,
)

iec61850_dep = declare_dependency(
    link_with: [iec61850_lib] + mms_lib,
    include_directories: inc_dirs,
    dependencies: core_deps,
)

# Exposed to the parent project (option-forwarding verification):
# true iff this subproject was configured with -Denable_security=true.
iec61850_security_enabled = get_option('enable_security')

# Tests
if get_option('enable_tests')
    subdir('tests')
endif

# Examples
math_dep = cc.find_library('m', required: false)
if get_option('enable_examples')
    example_names = ['goose_publisher', 'goose_subscriber',
                     'sv_publisher', 'sv_subscriber']
    foreach ex : example_names
        executable('example_' + ex,
            'examples/' + ex + '.c',
            include_directories: inc_dirs,
            link_with: [iec61850_lib] + mms_lib,
            dependencies: core_deps + [math_dep],
            c_args: ['-Wno-missing-prototypes', '-D_DEFAULT_SOURCE'],
            build_by_default: false,
        )
    endforeach

    # MMS-dependent examples
    if get_option('enable_mms')
        executable('example_mms_client_report',
            'examples/mms_client_report.c',
            include_directories: inc_dirs,
            link_with: [iec61850_lib] + mms_lib,
            dependencies: core_deps,
            c_args: ['-Wno-missing-prototypes'],
            build_by_default: false,
        )
    endif

    executable('goose_latency',
        'examples/latency/goose_latency.c',
        include_directories: inc_dirs,
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-missing-prototypes', '-D_DEFAULT_SOURCE'],
        build_by_default: false,
    )
endif

# Privileged AF_XDP socket daemon (requires xdp-graph-lib + libbpf)
if xgl_dep.found() and libbpf_dep.found()
    executable('xsk-daemon',
        'src/daemon/xsk_daemon.c',
        include_directories: inc_dirs,
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-missing-prototypes', '-D_DEFAULT_SOURCE', '-D_GNU_SOURCE'],
        install: true,
    )
endif

# Summary
summary({
    'Project': meson.project_name(),
    'Version': meson.project_version(),
    'C Standard': get_option('c_std'),
    'Build Type': get_option('buildtype'),
    'xdp-graph-lib': xgl_dep.found() ? 'found' : 'not found (XSK transport disabled)',
    'libbpf': libbpf_dep.found() ? libbpf_dep.version() : 'not found',
    'MMS': get_option('enable_mms') ? 'enabled' : 'disabled',
    'Security': get_option('enable_security') ? 'enabled' : 'disabled',
    'HSR/PRP': get_option('enable_hsr_prp') ? 'enabled' : 'disabled',
}, section: 'Configuration')
