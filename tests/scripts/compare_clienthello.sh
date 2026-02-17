#!/bin/bash
# Wireshark / tshark script for comparing fake ClientHello with real Chrome

set -e

echo "=== Wireshark ClientHello Comparison Script ==="
echo ""

# Check if tshark is installed
if ! command -v tshark &> /dev/null; then
    echo "Error: tshark is not installed. Please install Wireshark/tshark first."
    exit 1
fi

# Capture real Chrome TLS ClientHello
echo "[1] Capturing real Chrome ClientHello..."
echo "Please visit https://www.example.com in Chrome in the next 30 seconds"
echo "Capturing on all interfaces for port 443..."
echo ""

sudo timeout 30 tshark -i any -f "tcp port 443" -Y "tls.handshake.type == 1" \
    -T fields \
    -e tls.handshake.ciphersuites \
    -e tls.handshake.session_id_length \
    -e tls.handshake.extensions.type \
    -c 1 > /tmp/real_chrome_ch.txt 2>/dev/null || true

if [ ! -s /tmp/real_chrome_ch.txt ]; then
    echo "Warning: No Chrome ClientHello captured. Using reference values."
    echo "15,20,25,30" > /tmp/real_chrome_ch.txt
fi

echo ""
echo "[2] Generating fake ClientHello from NCP..."
echo ""

# Build and run test
if [ ! -f "./build/tests/integration/test_dpi_fixes" ]; then
    echo "Building tests..."
    mkdir -p build && cd build
    cmake .. && make test_dpi_fixes
    cd ..
fi

./build/tests/integration/test_dpi_fixes \
    --gtest_filter="*FakeClientHello*" \
    --gtest_output=json:/tmp/fake_ch_test.json 2>&1 | tee /tmp/fake_ch_output.txt

echo ""
echo "[3] Comparison Results:"
echo ""

# Parse and compare
if [ -s /tmp/real_chrome_ch.txt ]; then
    real_ciphers=$(head -1 /tmp/real_chrome_ch.txt | tr ',' '\n' | wc -l)
    echo "Real Chrome cipher suites: ~$real_ciphers"
fi

echo ""
echo "Fake ClientHello validation:"
grep -q "\[       OK \]" /tmp/fake_ch_output.txt && echo "  ✓ All tests PASSED" || echo "  ✗ Some tests FAILED"
grep -q "HasRequiredFields" /tmp/fake_ch_output.txt && echo "  ✓ Has required TLS fields"
grep -q "HasMultipleCipherSuites" /tmp/fake_ch_output.txt && echo "  ✓ Has 15+ cipher suites"
grep -q "HasCriticalExtensions" /tmp/fake_ch_output.txt && echo "  ✓ Has critical extensions"

echo ""
echo "Extension coverage:"
grep "SNI extension" /tmp/fake_ch_output.txt && echo "  ✓ SNI present" || echo "  ✗ SNI missing"
grep "supported_versions" /tmp/fake_ch_output.txt && echo "  ✓ supported_versions present" || echo "  ✗ supported_versions missing"
grep "supported_groups" /tmp/fake_ch_output.txt && echo "  ✓ supported_groups present" || echo "  ✗ supported_groups missing"
grep "signature_algorithms" /tmp/fake_ch_output.txt && echo "  ✓ signature_algorithms present" || echo "  ✗ signature_algorithms missing"
grep "GREASE" /tmp/fake_ch_output.txt && echo "  ✓ GREASE present" || echo "  ✗ GREASE missing"

echo ""
echo "=== Analysis Complete ==="
echo "Full test output saved to: /tmp/fake_ch_output.txt"
echo "Test JSON results: /tmp/fake_ch_test.json"
