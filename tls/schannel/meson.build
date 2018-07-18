tlsschannel_sources = [
  'gtlsmodule-schannel.c',
  'gtlsbackend-schannel.c',
  'gtlsdatabase-schannel.c',
  'gtlscertificate-schannel.c',
  'gtlsconnection-schannel.c',
  'gtlsclientconnection-schannel.c',
  'gtlsserverconnection-schannel.c',
  'gtlsutils-schannel.c',
]

schannel_args = ['-DSECURITY_WIN32=1']

platform_deps = [schannel_dep, gio, glib, gobject]

if gio_supports_plugins
  gioschannel = shared_module('gioschannel',
    tlsschannel_sources,
    dependencies: [tlsbase_dep, platform_deps],
    include_directories: [config_h_include, tlsbase_incdir],
    install: true,
    install_dir: giomoduledir,
    c_args: extra_args + common_flags + schannel_args,
  )
endif

gioschannel_static = static_library('gioschannel',
  tlsschannel_sources,
  dependencies: platform_deps,
  objects: tlsbase.extract_all_objects(),
  include_directories: [config_h_include, tlsbase_incdir],
  install: true,
  install_dir: giomoduledir,
  c_args: extra_args + common_flags + schannel_args + ['-DG_IO_MODULE_BUILD_STATIC'],
)
install_headers(['gioschannel.h'])
install_data(['gioschannel.vapi'], install_dir: join_paths(get_option('datadir'), 'vala', 'vapi'))
pkg = import('pkgconfig')
pkg.generate(filebase: 'gioschannel',
  name: 'gioschannel',
  version: meson.project_version(),
  description: 'GLib GIO TLS backend using the Windows SChannel API',
  requires: ['glib-2.0', 'gobject-2.0', 'gio-2.0'],
  libraries: [gioschannel_static]
)

gioschannel_inc = include_directories([ '.', '..' ])
gioschannel_dep = declare_dependency(link_with: gioschannel_static,
  include_directories: [ gioschannel_inc, config_h_include ],
  dependencies: [tlsbase_dep, schannel_dep, gio, glib, gobject ],
  compile_args: ['-DG_IO_MODULE_BUILD_STATIC'],
)

