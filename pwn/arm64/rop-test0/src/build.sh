`xcrun --sdk iphoneos -f clang` -arch arm64 \
      -isysroot `xcrun --sdk iphoneos --show-sdk-path` \
      -miphoneos-version-min=8.0 \
      -o dontpopme \
      dontpopme.c
`xcrun --sdk iphoneos -f codesign` -f -s - --entitlements entitlements.xml dontpopme
