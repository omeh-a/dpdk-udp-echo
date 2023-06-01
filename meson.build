project('udp-echo', 'c')

dpdk = dependency('libdpdk')

cc = meson.get_compiler('c')

# Declare lwip dependency
lwip = cc.find_library('lwip', dirs: meson.current_source_dir() + '/lwip/lwip-2.1.3')

sources = files('src/main.c', 'src/lwipopts.h', 'src/udpecho.h', 'src/udpecho.c')
executable('udp-echo', sources, dependencies: [dpdk, lwip_dep])