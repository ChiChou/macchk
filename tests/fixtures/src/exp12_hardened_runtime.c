// Experiment 12: Code signing with hardened runtime + entitlements
// Build, then sign with:
//   codesign -s - --options runtime --entitlements ent.plist exp12_hardened
// ent.plist should contain:
//   <key>com.apple.security.app-sandbox</key><true/>
#include <stdio.h>

int main(int argc, char **argv) {
    printf("hardened runtime binary\n");
    return 0;
}
