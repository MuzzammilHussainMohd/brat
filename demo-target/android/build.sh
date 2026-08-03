#!/bin/bash
# Build script for GlucoSense Viewer app
# Builds APK without Gradle using aapt, javac, d2j-jar2dex, apksigner
#
# Requirements:
# - OpenJDK 21 (for javac/keytool)
# - android-sdk-build-tools (for aapt, apksigner)
# - android-framework-res (for framework-res.apk)
# - dex2jar (for d2j-jar2dex)

set -e

cd "$(dirname "$0")"

# Paths
ANDROID_SDK="/usr/lib/android-sdk"
BUILD_TOOLS="$ANDROID_SDK/build-tools/29.0.3"
AAPT="$BUILD_TOOLS/aapt"
FRAMEWORK_RES="/usr/share/android-framework-res/framework-res.apk"

# Output dirs
BUILD_DIR="build"
GEN_DIR="$BUILD_DIR/gen"
CLASSES_DIR="$BUILD_DIR/classes"
OUT_DIR="$BUILD_DIR/out"
STUBS_DIR="stubs"

echo "=== GlucoSense Viewer Build ==="
echo ""

# Clean and create directories
rm -rf "$BUILD_DIR"
mkdir -p "$GEN_DIR" "$CLASSES_DIR" "$OUT_DIR" "$BUILD_DIR/stubs_classes"

# Step 1: Build Android stubs JAR
echo "[1/6] Building Android stubs..."
find "$STUBS_DIR" -name "*.java" > "$BUILD_DIR/stubs_sources.txt"
javac -source 8 -target 8 -d "$BUILD_DIR/stubs_classes" @"$BUILD_DIR/stubs_sources.txt" 2>/dev/null || true
jar cf "$BUILD_DIR/android.jar" -C "$BUILD_DIR/stubs_classes" .
echo "      Created: $BUILD_DIR/android.jar"

# Step 2: Generate R.java using aapt
echo "[2/6] Generating R.java..."
"$AAPT" package -f -m \
    -J "$GEN_DIR" \
    -M AndroidManifest.xml \
    -S res \
    -I "$FRAMEWORK_RES"
echo "      Generated: $GEN_DIR/com/glucosense/viewer/R.java"

# Step 3: Compile Java sources
echo "[3/6] Compiling Java sources..."
find src -name "*.java" > "$BUILD_DIR/sources.txt"
find "$GEN_DIR" -name "*.java" >> "$BUILD_DIR/sources.txt"

javac --release 8 \
    -Xlint:-options \
    -classpath "$BUILD_DIR/android.jar" \
    -d "$CLASSES_DIR" \
    @"$BUILD_DIR/sources.txt" 2>&1 | grep -v "^warning:" || true

# Verify compilation
if [ ! -d "$CLASSES_DIR/com" ]; then
    echo "ERROR: Compilation failed"
    exit 1
fi
echo "      Compiled to: $CLASSES_DIR"

# Step 4: Create JAR and convert to DEX
echo "[4/6] Converting to DEX..."
jar cf "$BUILD_DIR/classes.jar" -C "$CLASSES_DIR" .

if command -v d2j-jar2dex &> /dev/null; then
    d2j-jar2dex "$BUILD_DIR/classes.jar" -o "$BUILD_DIR/classes.dex" 2>/dev/null
elif [ -f "$BUILD_TOOLS/dx" ]; then
    "$BUILD_TOOLS/dx" --dex --output="$BUILD_DIR/classes.dex" "$BUILD_DIR/classes.jar"
elif command -v d8 &> /dev/null; then
    d8 --output "$BUILD_DIR" "$BUILD_DIR/classes.jar"
else
    echo "ERROR: No dex tool available"
    exit 1
fi
echo "      Created: $BUILD_DIR/classes.dex"

# Step 5: Package APK
echo "[5/6] Packaging APK..."
"$AAPT" package -f \
    -M AndroidManifest.xml \
    -S res \
    -I "$FRAMEWORK_RES" \
    -F "$OUT_DIR/app-unsigned.apk" 2>/dev/null

# Add DEX to APK
cp "$BUILD_DIR/classes.dex" "$OUT_DIR/"
cd "$OUT_DIR"
zip -j app-unsigned.apk classes.dex >/dev/null
rm classes.dex
cd - >/dev/null
echo "      Created: $OUT_DIR/app-unsigned.apk"

# Step 6: Sign APK
echo "[6/6] Signing APK..."
KEYSTORE="$BUILD_DIR/debug.keystore"
if [ ! -f "$KEYSTORE" ]; then
    keytool -genkeypair -v \
        -keystore "$KEYSTORE" \
        -alias androiddebugkey \
        -keyalg RSA \
        -keysize 2048 \
        -validity 10000 \
        -storepass android \
        -keypass android \
        -dname "CN=Debug, OU=Debug, O=Debug, L=Debug, ST=Debug, C=US" \
        2>/dev/null
fi

apksigner sign \
    --ks "$KEYSTORE" \
    --ks-key-alias androiddebugkey \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$OUT_DIR/glucosense-viewer.apk" \
    "$OUT_DIR/app-unsigned.apk"

# Verify
apksigner verify "$OUT_DIR/glucosense-viewer.apk" >/dev/null && echo "      Signature verified"

# Summary
APK_PATH="$(pwd)/$OUT_DIR/glucosense-viewer.apk"
APK_SIZE=$(du -h "$APK_PATH" | cut -f1)

echo ""
echo "=== Build Complete ==="
echo "APK:  $APK_PATH"
echo "Size: $APK_SIZE"
echo ""
echo "Install with:"
echo "  adb install -r $OUT_DIR/glucosense-viewer.apk"
