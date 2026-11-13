# SPDX-License-Identifier: BSD-2-Clause
# Tests for xdp-iec61850

test_inc = include_directories('unit')

# Unit tests — Phase 1: Containers
test_containers = executable('test_containers',
    'unit/test_containers.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('containers', test_containers, suite: 'unit')

# Unit tests — Phase 2: BER Codec
test_goose_ber = executable('test_goose_ber',
    'unit/test_goose_ber.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('goose_ber', test_goose_ber, suite: 'unit')

test_sv_ber = executable('test_sv_ber',
    'unit/test_sv_ber.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('sv_ber', test_sv_ber, suite: 'unit')

# Unit tests — Phase 3: GOOSE Protocol
test_goose_pubsub = executable('test_goose_pubsub',
    'unit/test_goose_pubsub.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('goose_pubsub', test_goose_pubsub, suite: 'unit')

# Unit tests — Phase 5: Sampled Values Protocol
test_sv_pubsub = executable('test_sv_pubsub',
    'unit/test_sv_pubsub.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('sv_pubsub', test_sv_pubsub, suite: 'unit')

# Unit test — Latency Statistics
test_latency_stats = executable('test_latency_stats',
    'unit/test_latency_stats.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('latency_stats', test_latency_stats, suite: 'unit')

# Unit test — Error Paths (always built)
test_error_paths = executable('test_error_paths',
    'unit/test_error_paths.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('error_paths', test_error_paths, suite: 'unit')

# Unit test — Subscriber Advanced (always built)
test_subscriber_advanced = executable('test_subscriber_advanced',
    'unit/test_subscriber_advanced.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('subscriber_advanced', test_subscriber_advanced, suite: 'unit')

# Unit test — IED Data Model (always built)
test_ied_data_model = executable('test_ied_data_model',
    'unit/test_ied_data_model.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('ied_data_model', test_ied_data_model, suite: 'unit')

# Unit test — Data Model Deep (always built)
test_data_model_deep = executable('test_data_model_deep',
    'unit/test_data_model_deep.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    c_args: ['-Wno-float-equal'],
)
test('data_model_deep', test_data_model_deep, suite: 'unit')

# Unit test — Data Attribute (always built)
test_data_attribute = executable('test_data_attribute',
    'unit/test_data_attribute.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('data_attribute', test_data_attribute, suite: 'unit')

# Unit test — CDC Factory (always built)
test_cdc_factory = executable('test_cdc_factory',
    'unit/test_cdc_factory.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('cdc_factory', test_cdc_factory, suite: 'unit')

test_cdc_all = executable('test_cdc_all',
    'unit/test_cdc_all.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('cdc_all', test_cdc_all, suite: 'unit')

test_ied_types = executable('test_ied_types',
    'unit/test_ied_types.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('ied_types', test_ied_types, suite: 'unit')

test_goose_retransmission = executable('test_goose_retransmission',
    'unit/test_goose_retransmission.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('goose_retransmission', test_goose_retransmission, suite: 'unit')

test_goose_publisher_ext = executable('test_goose_publisher_ext',
    'unit/test_goose_publisher_extended.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('goose_publisher_ext', test_goose_publisher_ext, suite: 'unit')

test_sv_publisher_ext = executable('test_sv_publisher_ext',
    'unit/test_sv_publisher_extended.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('sv_publisher_ext', test_sv_publisher_ext, suite: 'unit')

# Unit test — Logger
test_logger = executable('test_logger',
    'unit/test_logger.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('logger', test_logger, suite: 'unit')

# Unit test — System Monitor
test_system_monitor = executable('test_system_monitor',
    'unit/test_system_monitor.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('system_monitor', test_system_monitor, suite: 'unit')

# Unit test — Config Manager
test_config_manager = executable('test_config_manager',
    'unit/test_config_manager.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('config_manager', test_config_manager, suite: 'unit')

# Unit test — PTP Clock
test_ptp_clock = executable('test_ptp_clock',
    'unit/test_ptp_clock.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('ptp_clock', test_ptp_clock, suite: 'unit')

# Unit test — Packet I/O (raw + xsk lifecycle and error paths)
test_packet_io = executable('test_packet_io',
    'unit/test_packet_io.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('packet_io', test_packet_io, suite: 'unit')

# Integration test — GOOSE/SV Round-Trip (always built)
test_goose_roundtrip = executable('test_goose_roundtrip',
    'integration/test_goose_roundtrip.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('goose_roundtrip', test_goose_roundtrip, suite: 'integration')

# Integration test — GOOSE Subscriber Timeout (always built)
test_subscriber_timeout = executable('test_subscriber_timeout',
    'integration/test_subscriber_timeout.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

test('subscriber_timeout', test_subscriber_timeout, suite: 'integration')

# MMS-dependent tests (only if MMS is enabled)
if get_option('enable_mms')
    # Integration test — TCP Listener (requires MMS tcp_socket.c)
    test_transport_listener = executable('test_transport_listener',
        'integration/test_transport_listener.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: [thread_dep],
    )
    test('transport_listener', test_transport_listener, suite: 'integration')

    test_mms_file_service = executable('test_mms_file_service',
        'unit/test_mms_file_service.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_file_service', test_mms_file_service, suite: 'unit')

    test_mms_report_buffer = executable('test_mms_report_buffer',
        'unit/test_mms_report_buffer.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_report_buffer', test_mms_report_buffer, suite: 'unit')

    test_rcb_auto_config = executable('test_rcb_auto_config',
        'unit/test_rcb_auto_config.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('rcb_auto_config', test_rcb_auto_config, suite: 'unit',
         workdir: meson.project_source_root())

    test_mms_journal = executable('test_mms_journal',
        'unit/test_mms_journal.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_journal', test_mms_journal, suite: 'unit')

    test_mms_data_store = executable('test_mms_data_store',
        'unit/test_mms_data_store.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_data_store', test_mms_data_store, suite: 'unit')

    test_mms_ber = executable('test_mms_ber',
        'unit/test_mms_ber.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-conversion', '-Wno-sign-conversion'],
    )
    test('mms_ber', test_mms_ber, suite: 'unit')

    test_report_buffer_ext = executable('test_report_buffer_extended',
        'unit/test_report_buffer_extended.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('report_buffer_extended', test_report_buffer_ext, suite: 'unit')

    test_scl_parser = executable('test_scl_parser',
        'unit/test_scl_parser.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('scl_parser', test_scl_parser, suite: 'unit',
         workdir: meson.project_source_root())

    test_scl_ied_builder = executable('test_scl_ied_builder',
        'unit/test_scl_ied_builder.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('scl_ied_builder', test_scl_ied_builder, suite: 'unit',
         workdir: meson.project_source_root())

    # Unit test — Transport (TPKT, Session, Presentation)
    test_transport = executable('test_transport',
        'unit/test_transport.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('transport', test_transport, suite: 'unit')

    # Unit test — ISO Stack
    test_iso_stack = executable('test_iso_stack',
        'unit/test_iso_stack.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('iso_stack', test_iso_stack, suite: 'unit')

    # Unit test — TCP/ISO Coverage
    test_tcp_iso_cov = executable('test_tcp_iso_coverage',
        'unit/test_tcp_iso_coverage.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('tcp_iso_coverage', test_tcp_iso_cov, suite: 'unit')

    # Unit test — Coverage Gaps (publisher build_frame, security roundtrip, MMS BER)
    test_coverage_gaps = executable('test_coverage_gaps',
        'unit/test_coverage_gaps.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('coverage_gaps', test_coverage_gaps, suite: 'unit',
         workdir: meson.project_source_root())

    # Unit test — MMS Named Type Services
    test_mms_type_services = executable('test_mms_type_services',
        'unit/test_mms_type_services.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-conversion', '-Wno-sign-conversion'],
    )
    test('mms_type_services', test_mms_type_services, suite: 'unit')

    # Unit test — MMS Control Services
    test_mms_control = executable('test_mms_control',
        'unit/test_mms_control.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_control', test_mms_control, suite: 'unit')

    # Integration: RCB End-to-End
    test_rcb_e2e = executable('test_rcb_e2e',
        'integration/test_rcb_e2e.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('rcb_e2e', test_rcb_e2e, suite: 'integration')

    # Unit test — MMS Client (error paths + init)
    test_mms_client = executable('test_mms_client',
        'unit/test_mms_client.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_client', test_mms_client, suite: 'unit')

    # Unit tests — client async core + RCB enrollment (WP-S1 scaffolds,
    # extended by WP-1a / WP-1c)
    test_mms_client_core = executable('test_mms_client_core',
        'unit/test_mms_client_core.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_client_core', test_mms_client_core, suite: 'unit')

    test_mms_client_rcb = executable('test_mms_client_rcb',
        'unit/test_mms_client_rcb.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_client_rcb', test_mms_client_rcb, suite: 'unit')

    # Integration: MMS Client-Server E2E
    test_mms_e2e = executable('test_mms_e2e',
        'integration/test_mms_e2e.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_e2e', test_mms_e2e, suite: 'integration')

    # Unit test — Coverage Boost (sv_ber security, mms_server process_request,
    #   goose/sv subscriber frame processing)
    test_coverage_boost = executable('test_coverage_boost',
        'unit/test_coverage_boost.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-conversion', '-Wno-sign-conversion'],
    )
    test('coverage_boost', test_coverage_boost, suite: 'unit',
         workdir: meson.project_source_root())

    # Unit test — Coverage Boost 2 (goose_ber_decode allData types, goose_ber
    #   encode paths, key_manager sign/verify, mms_report RCB lifecycle)
    test_coverage_boost2 = executable('test_coverage_boost2',
        'unit/test_coverage_boost2.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('coverage_boost2', test_coverage_boost2, suite: 'unit',
         workdir: meson.project_source_root())

    # Integration: MMS Session Lifecycle
    test_mms_session = executable('test_mms_session',
        'integration/test_mms_session.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_session', test_mms_session, suite: 'integration')

    test_file_e2e = executable('test_file_e2e',
        'integration/test_file_e2e.c',
        include_directories: inc_dirs,
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('file_e2e', test_file_e2e, suite: 'integration')

    test_journal_e2e = executable('test_journal_e2e',
        'integration/test_journal_e2e.c',
        include_directories: inc_dirs,
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('journal_e2e', test_journal_e2e, suite: 'integration')

    # Integration: IED ACSI — SCL → IED model → MMS data store pipeline
    test_ied_acsi = executable('test_ied_acsi_integration',
        'integration/test_ied_acsi_integration.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('ied_acsi_integration', test_ied_acsi, suite: 'integration',
         workdir: meson.project_source_root())

    # Unit test — MMS Variable Binding Manager
    test_mms_variable_binding = executable('test_mms_variable_binding',
        'unit/test_mms_variable_binding.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_variable_binding', test_mms_variable_binding, suite: 'unit')

    # Integration: Bidirectional MMS/IED Binding
    test_bidirectional_binding = executable('test_bidirectional_binding',
        'integration/test_bidirectional_binding.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('bidirectional_binding', test_bidirectional_binding, suite: 'integration')

    # Integration: Phase 7 Combined Workflow + Monitoring
    test_phase7_monitoring = executable('test_phase7_monitoring',
        'integration/test_phase7_monitoring.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('phase7_monitoring', test_phase7_monitoring, suite: 'integration',
         is_parallel: false)
endif

# Security-dependent tests (only if security is enabled)
if get_option('enable_security')
    test_security_sign_verify = executable('test_security_sign_verify',
        'unit/test_security_sign_verify.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('security_sign_verify', test_security_sign_verify, suite: 'unit',
         workdir: meson.project_source_root())

    test_cert_manager = executable('test_cert_manager',
        'unit/test_cert_manager.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('cert_manager', test_cert_manager, suite: 'unit',
         workdir: meson.project_source_root())

    test_security_properties = executable('test_security_properties',
        'property/test_security_properties.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('security_properties', test_security_properties, suite: 'property',
         workdir: meson.project_source_root())

    test_key_manager = executable('test_key_manager',
        'unit/test_key_manager.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('key_manager', test_key_manager, suite: 'unit',
         workdir: meson.project_source_root())

    test_security_edge_cases = executable('test_security_edge_cases',
        'unit/test_security_edge_cases.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('security_edge_cases', test_security_edge_cases, suite: 'unit',
         workdir: meson.project_source_root())

    test_security_publisher = executable('test_security_publisher',
        'unit/test_security_publisher.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('security_publisher', test_security_publisher, suite: 'unit',
         workdir: meson.project_source_root())

    test_hmac_verify = executable('test_hmac_verify',
        'unit/test_hmac_verify.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('hmac_verify', test_hmac_verify, suite: 'unit')

    test_security_protocols = executable('test_security_protocols',
        'unit/test_security_protocols.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('security_protocols', test_security_protocols, suite: 'unit')

    # Integration: Secure GOOSE E2E
    test_secure_goose_e2e = executable('test_secure_goose_e2e',
        'integration/test_secure_goose_e2e.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('secure_goose_e2e', test_secure_goose_e2e, suite: 'integration',
         workdir: meson.project_source_root())
endif

# Unit test — YAML Parser (only if libyaml is available)
if libyaml_dep.found()
    test_yaml_parser = executable('test_yaml_parser',
        'unit/test_yaml_parser.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('yaml_parser', test_yaml_parser, suite: 'unit')
endif

# Unit test — HSR/PRP Wrapper (always built; stubs when xdp-hsr-prp absent)
test_hsr_prp = executable('test_hsr_prp',
    'unit/test_hsr_prp.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: core_deps,
)
test('hsr_prp', test_hsr_prp, suite: 'unit')

# Unit tests — 90-5 routable profiles (WP-S4 scaffolds, extended by
# WP-4a / WP-4b)
test_rgoose_ber = executable('test_rgoose_ber',
    'unit/test_rgoose_ber.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('rgoose_ber', test_rgoose_ber, suite: 'unit')

test_packet_io_udp = executable('test_packet_io_udp',
    'unit/test_packet_io_udp.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('packet_io_udp', test_packet_io_udp, suite: 'unit')

# Integration: Loopback tests (require root, build_by_default: false)
goose_loopback = executable('goose_loopback',
    'integration/goose_loopback.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    build_by_default: false,
)

sv_loopback = executable('sv_loopback',
    'integration/sv_loopback.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    build_by_default: false,
)

# Integration: IEC 61850 XDP graph (require root + BPF objects)
if libbpf_dep.found()
    # Pass build directory paths as defines so the test can find BPF objects
    graph_test_args = [
        '-DBPF_OBJ_DIR="' + meson.project_build_root() + '"',
        '-DIEC61850_BPF_DIR="' + meson.project_build_root() + '"',
    ]

    test_iec61850_graph = executable('test_iec61850_graph',
        'integration/test_iec61850_graph.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: graph_test_args + ['-Wno-format-truncation'],
    )
    test('iec61850_graph', test_iec61850_graph,
         suite: 'integration', is_parallel: false)
endif

# Integration: packet_io raw + veth (require root)
test_packet_io_raw_veth = executable('test_packet_io_raw_veth',
    'integration/test_packet_io_raw_veth.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

# Integration: packet_io XSK + veth (require root)
test_packet_io_xsk_veth = executable('test_packet_io_xsk_veth',
    'integration/test_packet_io_xsk_veth.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

# Integration: rootless AF_XDP fd inheritance (bad-magic test runs unprivileged;
# the other three tests require root for veth + AF_XDP bind)
test_xsk_inherited = executable('test_xsk_inherited',
    'integration/test_xsk_inherited.c',
    include_directories: [inc_dirs, test_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    c_args: ['-D_DEFAULT_SOURCE'],
)

# Register privileged tests (require root)
uid_result = run_command('id', '-u', check: false)
if uid_result.returncode() == 0 and uid_result.stdout().strip() == '0'
    test('goose_loopback', goose_loopback,
         suite: 'integration', is_parallel: false)
    test('sv_loopback', sv_loopback,
         suite: 'integration', is_parallel: false)
    test('packet_io_raw_veth', test_packet_io_raw_veth,
         suite: 'integration', is_parallel: false)
    test('packet_io_xsk_veth', test_packet_io_xsk_veth,
         suite: 'integration', is_parallel: false)
    test('xsk_inherited', test_xsk_inherited,
         suite: 'integration', is_parallel: false)
else
    # When not root, register but expect tests to skip gracefully (0 exit)
    test('packet_io_raw_veth', test_packet_io_raw_veth,
         suite: 'integration', is_parallel: false)
    test('packet_io_xsk_veth', test_packet_io_xsk_veth,
         suite: 'integration', is_parallel: false)
    test('xsk_inherited', test_xsk_inherited,
         suite: 'integration', is_parallel: false)
endif

# Fuzz targets (standalone mode — build but run as short test)
fuzz_goose_decoder = executable('fuzz_goose_decoder',
    'fuzz/fuzz_goose_decoder.c',
    include_directories: [inc_dirs],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    c_args: ['-Wno-missing-prototypes'],
    build_by_default: false,
)

fuzz_sv_decoder = executable('fuzz_sv_decoder',
    'fuzz/fuzz_sv_decoder.c',
    include_directories: [inc_dirs],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    c_args: ['-Wno-missing-prototypes'],
    build_by_default: false,
)

fuzz_goose_encoder = executable('fuzz_goose_encoder',
    'fuzz/fuzz_goose_encoder.c',
    include_directories: [inc_dirs],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    c_args: ['-Wno-missing-prototypes'],
    build_by_default: false,
)

# Fuzz target: 90-5 routable-profile decoders (WP-S4 scaffold; harness
# filled in by WP-4a)
fuzz_r_profile = executable('fuzz_r_profile',
    'fuzz/fuzz_r_profile.c',
    include_directories: [inc_dirs],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    c_args: ['-Wno-missing-prototypes', '-Wno-conversion',
             '-Wno-sign-conversion'],
    build_by_default: false,
)

test('fuzz_replay_r_profile', fuzz_r_profile,
     suite: 'fuzz',
     args: [meson.project_source_root() / 'tests/fuzz/corpora/r_profile'])

# Fuzz targets for the MMS/ISO/SCL surface (gated on enable_mms;
# scaffolding from WP-S0 — harnesses filled in by WP-0a/0b/0c)
if get_option('enable_mms')
    fuzz_mms_decoder = executable('fuzz_mms_decoder',
        'fuzz/fuzz_mms_decoder.c',
        include_directories: [inc_dirs],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-missing-prototypes', '-Wno-conversion',
                 '-Wno-sign-conversion'],
        build_by_default: false,
    )

    fuzz_iso_stack = executable('fuzz_iso_stack',
        'fuzz/fuzz_iso_stack.c',
        include_directories: [inc_dirs],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-missing-prototypes', '-Wno-conversion',
                 '-Wno-sign-conversion'],
        build_by_default: false,
    )

    fuzz_scl_parser = executable('fuzz_scl_parser',
        'fuzz/fuzz_scl_parser.c',
        include_directories: [inc_dirs],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-missing-prototypes', '-Wno-conversion',
                 '-Wno-sign-conversion'],
        build_by_default: false,
    )

    # Fuzz corpus replay (suite 'fuzz'): deterministic regression check.
    # Feeds every committed seed to its harness once. Configure the
    # builddir with -Db_sanitize=address for full memory-safety effect.
    fuzz_replay_targets = [
        ['fuzz_replay_mms_decoder', fuzz_mms_decoder, 'tests/fuzz/corpora/mms_decoder'],
        ['fuzz_replay_iso_stack', fuzz_iso_stack, 'tests/fuzz/corpora/iso_stack'],
        ['fuzz_replay_scl_parser', fuzz_scl_parser, 'tests/fuzz/corpora/scl_parser'],
    ]
    foreach t : fuzz_replay_targets
        test(t[0], t[1], suite: 'fuzz',
             args: [meson.project_source_root() / t[2]])
    endforeach
endif

# Benchmark — BER codec throughput
bench_ber_codec = executable('bench_ber_codec',
    'bench/bench_ber_codec.c',
    include_directories: [inc_dirs],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
    c_args: ['-Wno-missing-prototypes', '-O2'],
    build_by_default: false,
)

# Benchmark — Performance latency/throughput (GOOSE, SV, MMS)
if get_option('enable_mms')
    bench_performance = executable('benchmark_performance',
        'benchmark/benchmark_performance.c',
        include_directories: [inc_dirs],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
        c_args: ['-Wno-missing-prototypes'],
    )
    test('benchmark_performance', bench_performance, suite: 'benchmark',
         is_parallel: false, timeout: 120)
endif

# Property-based tests — Phase 6
property_tests = [
    ['goose_properties', 'property/test_goose_properties.c'],
    ['sv_properties', 'property/test_sv_properties.c'],
    ['ber_codec_properties', 'property/test_ber_codec_properties.c'],
    ['malformed_inputs', 'property/test_malformed_inputs.c'],
    ['state_machine_properties', 'property/test_state_machine_properties.c'],
    ['subscriber_filtering_properties', 'property/test_subscriber_filtering_properties.c'],
]

foreach t : property_tests
    exe = executable('test_' + t[0],
        t[1],
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: [thread_dep],
    )
    test(t[0], exe, suite: 'property')
endforeach

# ============================================================
# Interop tests — subprocess isolation against libiec61850 (GPL)
# Tests skip with exit 77 if libiec61850 helpers not found.
# GOOSE/SV tests require root; MMS tests use TCP loopback.
# ============================================================

interop_inc = include_directories('interop')

# GOOSE interop: libiec61850 pub → xdp sub (12 scenarios)
test_goose_interop_sub = executable('test_goose_interop_sub',
    'interop/goose/test_goose_interop_sub.c',
    include_directories: [inc_dirs, test_inc, interop_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('goose_interop_sub', test_goose_interop_sub,
     suite: 'interop', is_parallel: false)

# GOOSE interop: xdp pub → libiec61850 sub (9 scenarios)
test_goose_interop_pub = executable('test_goose_interop_pub',
    'interop/goose/test_goose_interop_pub.c',
    include_directories: [inc_dirs, test_inc, interop_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('goose_interop_pub', test_goose_interop_pub,
     suite: 'interop', is_parallel: false)

# SV interop: libiec61850 pub → xdp sub (7 scenarios)
test_sv_interop_sub = executable('test_sv_interop_sub',
    'interop/sv/test_sv_interop_sub.c',
    include_directories: [inc_dirs, test_inc, interop_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('sv_interop_sub', test_sv_interop_sub,
     suite: 'interop', is_parallel: false)

# SV interop: xdp pub → libiec61850 sub (4 scenarios)
test_sv_interop_pub = executable('test_sv_interop_pub',
    'interop/sv/test_sv_interop_pub.c',
    include_directories: [inc_dirs, test_inc, interop_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('sv_interop_pub', test_sv_interop_pub,
     suite: 'interop', is_parallel: false)

# SV interop: live veth pub/sub (2 scenarios — SL-01, SL-02)
test_sv_interop_live = executable('test_sv_interop_live',
    'interop/sv/test_sv_interop_live.c',
    include_directories: [inc_dirs, test_inc, interop_inc],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
test('sv_interop_live', test_sv_interop_live,
     suite: 'interop', is_parallel: false)

# MMS interop tests (require MMS enabled)
if get_option('enable_mms')
    # MMS interop: xdp client → libiec61850 server (9 scenarios)
    test_mms_interop_client = executable('test_mms_interop_client',
        'interop/mms/test_mms_interop_client.c',
        include_directories: [inc_dirs, test_inc, interop_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_interop_client', test_mms_interop_client,
         suite: 'interop', is_parallel: false)

    # MMS interop: libiec61850 client → xdp server (8 scenarios)
    test_mms_interop_server = executable('test_mms_interop_server',
        'interop/mms/test_mms_interop_server.c',
        include_directories: [inc_dirs, test_inc, interop_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_interop_server', test_mms_interop_server,
         suite: 'interop', is_parallel: false)

    # MMS reporting interop: xdp client → libiec61850 server (WP-1d)
    test_mms_interop_reporting = executable('test_mms_interop_reporting',
        'interop/mms/test_mms_interop_reporting.c',
        include_directories: [inc_dirs, test_inc, interop_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('mms_interop_reporting', test_mms_interop_reporting,
         suite: 'interop', is_parallel: false)
endif

# Wire publisher programs (used by wire capture tests)
goose_wire_pub = executable('goose_wire_pub',
    'interop/wire/goose_wire_pub.c',
    include_directories: [inc_dirs],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)
sv_wire_pub = executable('sv_wire_pub',
    'interop/wire/sv_wire_pub.c',
    include_directories: [inc_dirs],
    link_with: [iec61850_lib] + mms_lib,
    dependencies: [thread_dep],
)

# Wire capture tests (shell scripts, require root + tshark)
wire_test_scripts = [
    ['wire_goose', 'interop/wire/test_wire_goose.sh'],
    ['wire_sv', 'interop/wire/test_wire_sv.sh'],
    ['wire_mms', 'interop/wire/test_wire_mms.sh'],
]
wire_test_env = environment()
wire_test_env.set('MESON_BUILD_ROOT', meson.project_build_root())
libiec_build = get_option('libiec61850_build_dir')
if libiec_build != ''
    wire_test_env.set('LIBIEC61850_BUILD_DIR', libiec_build)
endif

foreach t : wire_test_scripts
    test(t[0], find_program('sh'), args: [files(t[1])],
         suite: 'interop', is_parallel: false,
         workdir: meson.project_source_root(),
         env: wire_test_env)
endforeach

# Wire cross-validation tests (require libiec61850 + root/tshark)
wire_xval_scripts = [
    ['wire_goose_xval', 'interop/wire/test_wire_goose_xval.sh'],
    ['wire_sv_xval', 'interop/wire/test_wire_sv_xval.sh'],
    ['wire_mms_xval', 'interop/wire/test_wire_mms_xval.sh'],
]
foreach t : wire_xval_scripts
    test(t[0], find_program('sh'), args: [files(t[1])],
         suite: 'interop', is_parallel: false,
         workdir: meson.project_source_root(),
         env: wire_test_env)
endforeach

# ============================================================
# Long-duration stress tests (suite: 'longrun', timeout: 600)
# Require MMS for client/server scenario.
# Duration configurable via LONGRUN_DURATION_SEC (default: 10).
# ============================================================

if get_option('enable_mms')
    test_long_duration = executable('test_long_duration',
        'longrun/test_long_duration.c',
        include_directories: [inc_dirs, test_inc],
        link_with: [iec61850_lib] + mms_lib,
        dependencies: core_deps,
    )
    test('long_duration', test_long_duration,
         suite: 'longrun', timeout: 600, is_parallel: false)
endif
