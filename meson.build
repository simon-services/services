project('reqrep','c')

c = meson.get_compiler('c')

nng_dep = declare_dependency(dependencies: c.find_library('nng', dirs: join_paths(meson.current_source_dir(),'libs')),include_directories: ['include'])
mbedcrypto_dep = declare_dependency(dependencies: c.find_library('mbedcrypto', dirs: join_paths(meson.current_source_dir(),'libs')),include_directories: ['include'])
mbedtls_dep = declare_dependency(dependencies: c.find_library('mbedtls', dirs: join_paths(meson.current_source_dir(),'libs')),include_directories: ['include'])
mbedx509_dep = declare_dependency(dependencies: c.find_library('mbedx509', dirs: join_paths(meson.current_source_dir(),'libs')),include_directories: ['include'])
threads_dep = dependency('threads')

executable('reqrep','reqrep.c', dependencies: [nng_dep,mbedcrypto_dep,mbedtls_dep,mbedx509_dep,threads_dep])
