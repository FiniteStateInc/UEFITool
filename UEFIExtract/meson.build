executable(
  'UEFIExtract',
  sources: [
    'uefiextract_main.cpp',
    'ffsdumper.cpp',
    'ffsfocusedextractor.cpp',
    'ffssbomparser.cpp',
    'uefidump.cpp',
  ],
  link_with: [
    lzma,
    bstrlib,
    uefitoolcommon,
  ],
  dependencies: [
    zlib,
  ],
  install: true,
)
