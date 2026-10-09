# Port additions to the vendored availability DSL.
#
# AvailabilityVersions-157.2 (the newest published tag) ends its macOS list at
# 14.3, but the vendored libc is newer: gen/fts.c uses
# DYLD_MACOSX_VERSION_15_4. Appending the version here makes Apple's own
# generator emit DYLD_MACOSX_VERSION_15_4 / dyld_platform_version_macOS_15_4
# with its documented encoding (major << 16 | minor << 8 | patch), the same
# encoding it emits for 14.3 as 0x000e0300. No set entry is added: version sets
# describe software updates, and no published set covers 15.4.
version     macos               15.4
