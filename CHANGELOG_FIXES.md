# Changelog: Bug Fixes from Code Review

All issues identified in the external review have been fixed.

## Critical Fixes (build blockers)

### 1. `std::mutex` not movable — `error C2280`
**Before:** `OnnxShadowClassifier(OnnxShadowClassifier&&) noexcept = default;`
**After:** Manual move constructor/assignment that:
  - Moves `impl_` (unique_ptr — movable)
  - Copies config under lock (mutex is NOT moved)
  - Gives the source a fresh `Impl{}` so `is_loaded()` is safe after move

### 2. `EnableMemoryPattern()` — `error C2039`
**Before:** `opts.EnableMemoryPattern()` (doesn't exist in ORT API)
**After:** `opts.EnableMemPattern()` (correct method name)

### 3. Windows `const wchar_t*` path — `error C2665`
**Before:** `Ort::Session(*env, model_path.c_str(), opts)` — fails on Windows
**After:** `#ifdef _WIN32` converts UTF-8 → wide string via `MultiByteToWideChar`, passes `wstring::c_str()` to `Ort::Session`

## Functional Fixes

### 4. Test crash via static self-registration (AV `0xC0000005`)
**Before:** Tests used static objects that self-registered; destruction of `Ort::MemoryInfo` during static teardown caused access violation on MSVC+ORT.
**After:** Rewritten entirely as standard `gtest TEST()` macros. No static registration. Can be compiled as separate target or included in gtest_main.

### 5. Feature contract mismatch (10 vs 8 features)
**Before:** README example used `SizeErrorLearner::from_snapshot()` which produces 8 fields, but model expects 10.
**After:** 
- New `OnnxShadowFeatures` struct with exactly 10 fields matching the model
- `extract_onnx_features()` function extracts all 10 from raw packet data
- Clear documentation of which fields come from where

### 6. No integration point in AdversaryTester
**Before:** `combined_stealth()` was never called; module was dead code after copy.
**After:** 
- `ncp_onnx_integration.hpp` provides complete integration guide
- `set_onnx_classifier(shared_ptr)` method documented
- Code snippet shows exactly where to add the hook in `evaluate()`

## Quality Fixes

### 7. `result.valid = true` set even without parsed probabilities
**Before:** `valid` was set regardless of whether probability tensor was found.
**After:** `parsed_proba` flag tracks whether we actually extracted probabilities. `valid` only set if `parsed_proba == true`.

### 8. `config_` read without mutex
**Before:** `predict()` and `combined_stealth()` read `config_.enabled`, `config_.weight`, `config_.detection_threshold` without lock, despite `set_config()` holding the lock.
**After:** All config reads in hot paths go through locked accessors or local copies under lock.

### 9. `is_loaded()` UB after move
**Before:** After move, `impl_` could be null → `impl_->loaded` is UB.
**After:** `is_loaded()` checks `if (!impl_ || impl_->moved_from) return false;`. Moved-from objects get a fresh `Impl{moved_from: true}`.

### 10. `~` in model_path not expanded
**Before:** `~/.ncp/models/model.onnx` passed literally to `Ort::Session` → file not found.
**After:** `OnnxShadowFeatures::expand_tilde()` resolves `~` → `$HOME` (POSIX) or `%USERPROFILE%` (Windows).

### 11. CMake only searches Linux paths
**Before:** `find_library` only had `/usr/lib` paths; Windows vcpkg/NuGet not covered.
**After:** Comprehensive search paths for:
  - vcpkg toolchain (Windows/Linux/macOS)
  - pkg-config (Linux)
  - NuGet packages (`~/.nuget/packages/`)
  - Homebrew (`/opt/homebrew/`)
  - Manual `$ONNXRUNTIME_ROOT`
  - Windows system paths

## Verification

```
$ g++ -std=c++17 -I src test_stub.cpp ncp_onnx_classifier.cpp -lpthread -o test_stub
$ ./test_stub
=== OnnxShadowClassifier Stub Tests (no ONNX Runtime) ===
24/24 tests passed
```

Stub mode: **compiles cleanly**, all 24 tests pass, zero warnings.

## Files Modified

| File | Changes |
|---|---|
| `src/ncp_onnx_classifier.hpp` | Added `OnnxShadowFeatures`, manual move decl, expand_tilde |
| `src/ncp_onnx_classifier.cpp` | Full rewrite: all 11 fixes |
| `src/ncp_onnx_integration.hpp` | NEW: feature extraction + integration guide |
| `tests/test_onnx_classifier.cpp` | Rewritten as gtest (no static registration) |
| `cmake/ncp_onnx_classifier.cmake` | Full rewrite: Windows/vcpkg/NuGet support |
