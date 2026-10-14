{
  'targets': [
    {
      'target_name': 'kerberos',
      'type': 'loadable_module',
      'include_dirs': [
        "<!(node -p \"require('node-addon-api').include_dir\")",
        '<(kerberos_include_dir)'
      ],
      'sources': [
        'vendor/kerberos/src/kerberos.cc'
      ],
      'variables': {
        'ARCH': '<(host_arch)',
        'kerberos_use_rtld%': 'true',
        'kerberos_include_dir%': ''
      },
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'CLANG_CXX_LIBRARY': 'libc++',
        'MACOSX_DEPLOYMENT_TARGET': '11',
        'GCC_SYMBOLS_PRIVATE_EXTERN': 'YES'
      },
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions', '-std=gnu++20' ],
      'cflags_cc+': [ '-std=gnu++2a' ],
      'msvs_configuration_attributes': {
        'SpectreMitigation': 'Spectre'
      },
      'msvs_settings': {
        'VCCLCompilerTool': {
          'ExceptionHandling': 1,
          'AdditionalOptions': [ '/guard:cf', '/w34244', '/w34267', '/ZH:SHA_256' ]
        },
        'VCLinkerTool': {
          'AdditionalOptions': [ '/guard:cf' ]
        }
      },
      'conditions': [
        ['OS=="mac"', { 'cflags+': ['-fvisibility=hidden'] }],
        ['OS=="mac" or OS=="linux" or OS=="freebsd"', {
          'sources': [
            'vendor/kerberos/src/unix/base64.cc',
            'vendor/kerberos/src/unix/kerberos_gss.cc',
            'vendor/kerberos/src/unix/kerberos_unix.cc'
          ]
        }],
        ['(OS=="mac") or ((OS=="linux" or OS=="freebsd") and kerberos_use_rtld!="true")', {
          'link_settings': { 'libraries': [ '-lkrb5', '-lgssapi_krb5' ] }
        }],
        ['(OS=="linux" or OS=="freebsd") and (kerberos_use_rtld=="true")', {
          'defines': ['KERBEROS_USE_RTLD=1'],
          'link_settings': { 'libraries': [ '-ldl' ] }
        }],
        ['OS=="win"', {
          'sources': [
            'vendor/kerberos/src/win32/kerberos_sspi.cc',
            'vendor/kerberos/src/win32/kerberos_win32.cc'
          ],
          'link_settings': { 'libraries': [ '-lcrypt32', '-lsecur32', '-lshlwapi' ] }
        }]
      ]
    }
  ]
}
