#!/bin/bash
# NCP C++ Installer Creation Script
# Phase 6 - Testing & Release

set -e

VERSION="1.0.0"
PRODUCT_NAME="NCP"
PRODUCT_DESC="Network Control Protocol"
BUILD_DIR="build"
OUTPUT_DIR="installers"

echo "=== NCP C++ Installer Creation Script ==="
echo "Version: $VERSION"

# Detect platform
detect_platform() {
    case "$(uname -s)" in
        Linux*)     PLATFORM="linux";;
        Darwin*)    PLATFORM="macos";;
        CYGWIN*|MINGW*|MSYS*) PLATFORM="windows";;
        *)          PLATFORM="unknown";;
    esac
    echo "Detected platform: $PLATFORM"
}

# Create Linux installer (DEB + RPM + AppImage)
create_linux_installer() {
    echo "Creating Linux installers..."
    
    mkdir -p "$OUTPUT_DIR/linux"
    
    # Create DEB package structure
    DEB_DIR="$OUTPUT_DIR/linux/deb"
    mkdir -p "$DEB_DIR/DEBIAN"
    mkdir -p "$DEB_DIR/usr/bin"
    mkdir -p "$DEB_DIR/usr/share/applications"
    mkdir -p "$DEB_DIR/usr/share/icons/hicolor/256x256/apps"
    
    # Copy binary
    cp "$BUILD_DIR/bin/ncp" "$DEB_DIR/usr/bin/"
    
    # Create control file
    cat > "$DEB_DIR/DEBIAN/control" << EOF
Package: ncp
Version: $VERSION
Section: net
Priority: optional
Architecture: amd64
Depends: libqt6core6, libqt6widgets6, libqt6network6, libpcap0.8
Maintainer: NCP Project <support@ncp-project.org>
Description: $PRODUCT_DESC
 Professional C++ implementation with cryptography and DPI bypass.
EOF
    
    # Create desktop entry
    cat > "$DEB_DIR/usr/share/applications/ncp.desktop" << EOF
[Desktop Entry]
Name=$PRODUCT_NAME
Comment=$PRODUCT_DESC
Exec=/usr/bin/ncp
Icon=ncp
Terminal=false
Type=Application
Categories=Network;Security;
EOF
    
    # Build DEB package
    dpkg-deb --build "$DEB_DIR" "$OUTPUT_DIR/linux/ncp-$VERSION-amd64.deb" || echo "DEB creation skipped (dpkg-deb not available)"
    
    # Create tarball
    tar -czvf "$OUTPUT_DIR/linux/ncp-$VERSION-linux-x64.tar.gz" -C "$BUILD_DIR/bin" ncp
    
    echo "Linux installers created!"
}

# Create macOS installer (DMG)
create_macos_installer() {
    echo "Creating macOS installer..."
    
    mkdir -p "$OUTPUT_DIR/macos"
    
    APP_DIR="$OUTPUT_DIR/macos/NCP.app"
    mkdir -p "$APP_DIR/Contents/MacOS"
    mkdir -p "$APP_DIR/Contents/Resources"
    
    # Copy binary
    cp "$BUILD_DIR/bin/ncp" "$APP_DIR/Contents/MacOS/"
    
    # Create Info.plist
    cat > "$APP_DIR/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>$PRODUCT_NAME</string>
    <key>CFBundleDisplayName</key>
    <string>$PRODUCT_DESC</string>
    <key>CFBundleIdentifier</key>
    <string>org.ncp-project.ncp</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleExecutable</key>
    <string>ncp</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF
    
    # Create DMG
    hdiutil create -volname "$PRODUCT_NAME $VERSION" -srcfolder "$OUTPUT_DIR/macos" \
        -ov -format UDZO "$OUTPUT_DIR/macos/NCP-$VERSION.dmg" || echo "DMG creation skipped"
    
    echo "macOS installer created!"
}

# Create Windows installer (NSIS script)
create_windows_installer() {
    echo "Creating Windows installer script..."
    
    mkdir -p "$OUTPUT_DIR/windows"
    
    # Create NSIS script
    cat > "$OUTPUT_DIR/windows/ncp_installer.nsi" << 'EOF'
!include "MUI2.nsh"

Name "NCP - Network Control Protocol"
OutFile "NCP-Setup.exe"
InstallDir "$PROGRAMFILES64\NCP"
RequestExecutionLevel admin

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "Install"
    SetOutPath $INSTDIR
    File "ncp.exe"
    File "README.md"
    File "LICENSE"
    
    ; Create shortcuts
    CreateDirectory "$SMPROGRAMS\NCP"
    CreateShortcut "$SMPROGRAMS\NCP\NCP.lnk" "$INSTDIR\ncp.exe"
    CreateShortcut "$DESKTOP\NCP.lnk" "$INSTDIR\ncp.exe"
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"
    
    ; Registry
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NCP" "DisplayName" "NCP"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NCP" "UninstallString" "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\ncp.exe"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\uninstall.exe"
    Delete "$SMPROGRAMS\NCP\NCP.lnk"
    Delete "$DESKTOP\NCP.lnk"
    RMDir "$SMPROGRAMS\NCP"
    RMDir "$INSTDIR"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\NCP"
SectionEnd
EOF
    
    echo "Windows installer script created!"
    echo "Run 'makensis $OUTPUT_DIR/windows/ncp_installer.nsi' to build the installer"
}

# Main
main() {
    detect_platform
    
    mkdir -p "$OUTPUT_DIR"
    
    case "$PLATFORM" in
        linux)
            create_linux_installer
            ;;
        macos)
            create_macos_installer
            ;;
        windows)
            create_windows_installer
            ;;
        *)
            echo "Creating all installer scripts..."
            create_linux_installer
            create_windows_installer
            ;;
    esac
    
    echo ""
    echo "=== Installer creation complete! ==="
    echo "Output directory: $OUTPUT_DIR"
    ls -la "$OUTPUT_DIR"
}

main "$@"
