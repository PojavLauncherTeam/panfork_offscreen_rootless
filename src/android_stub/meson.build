if with_android_stub
  stub_libs = []

  foreach lib : ['hardware', 'log', 'nativewindow']
    stub_libs += shared_library(
      lib,
      files(lib + '_stub.cpp'),
      include_directories : inc_include,
      install : false,
    )
  endforeach

  dep_android = declare_dependency(
    link_with : stub_libs,
  )
endif
