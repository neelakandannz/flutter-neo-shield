import 'dart:js_interop';

import 'package:flutter/services.dart';
import 'package:flutter_web_plugins/flutter_web_plugins.dart';
import 'package:web/web.dart' as web;

import 'src/platform/shield_codec.dart';

/// Web platform implementation of flutter_neo_shield.
///
/// Uses `package:web` + `dart:js_interop` for full WASM compatibility.
///
/// Browser sandboxing limits detection capability (~50%) compared to native
/// platforms, but several meaningful checks are still possible:
///
/// - **Debugger**: DevTools open detection via window size heuristic
/// - **Root/Jailbreak**: N/A on web — always returns false
/// - **Emulator**: Bot/automation detection (navigator.webdriver)
/// - **Frida**: N/A on web — always returns false
/// - **Hooks**: Native function override / prototype tampering detection
/// - **Integrity**: Script injection detection, DOM integrity
/// - **Developer Mode**: DevTools open detection (alias of debugger check)
/// - **Signature**: Native API prototype tampering detection
/// - **Native Debug**: Timing anomaly detection
/// - **Network Threats**: WebRTC availability / proxy heuristic
///
/// Screen protection uses CSS-based content hiding (limited effectiveness).
/// Memory operations use Dart-side wipe (no native secure memory on web).
class FlutterNeoShieldWeb {
  // Decoded method names (cached once at class init).
  static final String _mDebugger = ShieldCodec.d(ShieldCodec.mCheckDebugger);
  static final String _mRoot = ShieldCodec.d(ShieldCodec.mCheckRoot);
  static final String _mEmulator = ShieldCodec.d(ShieldCodec.mCheckEmulator);
  static final String _mFrida = ShieldCodec.d(ShieldCodec.mCheckFrida);
  static final String _mHooks = ShieldCodec.d(ShieldCodec.mCheckHooks);
  static final String _mIntegrity = ShieldCodec.d(ShieldCodec.mCheckIntegrity);
  static final String _mDevMode = ShieldCodec.d(ShieldCodec.mCheckDeveloperMode);
  static final String _mSignature = ShieldCodec.d(ShieldCodec.mCheckSignature);
  static final String _mNativeDbg = ShieldCodec.d(ShieldCodec.mCheckNativeDebug);
  static final String _mNetwork = ShieldCodec.d(ShieldCodec.mCheckNetworkThreats);
  static final String _mEnableProt = ShieldCodec.d(ShieldCodec.mEnableScreenProtection);
  static final String _mDisableProt = ShieldCodec.d(ShieldCodec.mDisableScreenProtection);
  static final String _mIsActive = ShieldCodec.d(ShieldCodec.mIsScreenProtectionActive);
  static final String _mEnableGuard = ShieldCodec.d(ShieldCodec.mEnableAppSwitcherGuard);
  static final String _mDisableGuard = ShieldCodec.d(ShieldCodec.mDisableAppSwitcherGuard);
  static final String _mIsRecorded = ShieldCodec.d(ShieldCodec.mIsScreenBeingRecorded);
  static final String _mAllocate = ShieldCodec.d(ShieldCodec.mAllocateSecure);
  static final String _mRead = ShieldCodec.d(ShieldCodec.mReadSecure);
  static final String _mWipe = ShieldCodec.d(ShieldCodec.mWipeSecure);
  static final String _mWipeAll = ShieldCodec.d(ShieldCodec.mWipeAll);

  // Location decoded method names
  static final String _mFakeLoc = ShieldCodec.d(ShieldCodec.mCheckFakeLocation);
  static final String _mMockProv = ShieldCodec.d(ShieldCodec.mCheckMockProvider);
  static final String _mSpoofApps = ShieldCodec.d(ShieldCodec.mCheckSpoofingApps);
  static final String _mLocHooks = ShieldCodec.d(ShieldCodec.mCheckLocationHooks);
  static final String _mGpsAnom = ShieldCodec.d(ShieldCodec.mCheckGpsAnomaly);
  static final String _mSensorFus = ShieldCodec.d(ShieldCodec.mCheckSensorFusion);
  static final String _mTempAnom = ShieldCodec.d(ShieldCodec.mCheckTemporalAnomaly);

  // New v2.0.0 method names
  static final String _mOverlay = ShieldCodec.d(ShieldCodec.mCheckOverlay);
  static final String _mClickjack = ShieldCodec.d(ShieldCodec.mCheckClickjacking);
  static final String _mAccessibility = ShieldCodec.d(ShieldCodec.mCheckAccessibility);
  static final String _mKeyboard = ShieldCodec.d(ShieldCodec.mCheckKeyboard);
  static final String _mKeylogger = ShieldCodec.d(ShieldCodec.mCheckKeylogger);
  static final String _mCodeInject = ShieldCodec.d(ShieldCodec.mCheckCodeInjection);
  static final String _mObfuscation = ShieldCodec.d(ShieldCodec.mCheckObfuscation);

  /// Registers all method channel handlers for RASP, screen, memory, and location.
  static void registerWith(Registrar registrar) {
    // RASP channel
    final raspChannel = MethodChannel(
      ShieldCodec.d(ShieldCodec.chRasp),
      const StandardMethodCodec(),
      registrar,
    );
    raspChannel.setMethodCallHandler(_handleRaspCall);

    // Screen channel
    final screenChannel = MethodChannel(
      ShieldCodec.d(ShieldCodec.chScreen),
      const StandardMethodCodec(),
      registrar,
    );
    screenChannel.setMethodCallHandler(_handleScreenCall);

    // Memory channel
    final memoryChannel = MethodChannel(
      ShieldCodec.d(ShieldCodec.chMemory),
      const StandardMethodCodec(),
      registrar,
    );
    memoryChannel.setMethodCallHandler(_handleMemoryCall);

    // Location channel
    final locationChannel = MethodChannel(
      ShieldCodec.d(ShieldCodec.chLocation),
      const StandardMethodCodec(),
      registrar,
    );
    locationChannel.setMethodCallHandler(_handleLocationCall);

    // New v2.0.0 channels
    final secureStorageChannel = MethodChannel(
      ShieldCodec.d(ShieldCodec.chSecureStorage),
      const StandardMethodCodec(),
      registrar,
    );
    secureStorageChannel.setMethodCallHandler(_handleSecureStorageCall);

    final biometricChannel = MethodChannel(
      ShieldCodec.d(ShieldCodec.chBiometric),
      const StandardMethodCodec(),
      registrar,
    );
    biometricChannel.setMethodCallHandler(_handleBiometricCall);

    final deviceBindingChannel = MethodChannel(
      ShieldCodec.d(ShieldCodec.chDeviceBinding),
      const StandardMethodCodec(),
      registrar,
    );
    deviceBindingChannel.setMethodCallHandler(_handleDeviceBindingCall);
  }

  // ---------------------------------------------------------------------------
  // RASP method handler
  // ---------------------------------------------------------------------------

  static Future<dynamic> _handleRaspCall(MethodCall call) async {
    final m = call.method;
    if (m == _mDebugger) return _checkDebugger();
    if (m == _mRoot) return false;
    if (m == _mEmulator) return _checkEmulator();
    if (m == _mFrida) return false;
    if (m == _mHooks) return _checkHooks();
    if (m == _mIntegrity) return _checkIntegrity();
    if (m == _mDevMode) return _checkDevTools();
    if (m == _mSignature) return _checkSignature();
    if (m == _mNativeDbg) return _checkNativeDebug();
    if (m == _mNetwork) return _checkNetworkThreats();
    // New v2.0.0 checks
    if (m == _mOverlay) return false; // N/A on web
    if (m == _mClickjack) return _checkClickjacking();
    if (m == _mAccessibility) return false;
    if (m == _mKeyboard) return false;
    if (m == _mKeylogger) return false;
    if (m == _mCodeInject) return false;
    if (m == _mObfuscation) return false;
    throw PlatformException(
      code: 'UNIMPLEMENTED',
      message: '${call.method} is not implemented on web',
    );
  }

  // ---------------------------------------------------------------------------
  // Screen method handler
  // ---------------------------------------------------------------------------

  static bool _screenProtectionActive = false;

  static Future<dynamic> _handleScreenCall(MethodCall call) async {
    final m = call.method;
    if (m == _mEnableProt) return _enableScreenProtection();
    if (m == _mDisableProt) return _disableScreenProtection();
    if (m == _mIsActive) return _screenProtectionActive;
    if (m == _mEnableGuard) return _enableScreenProtection();
    if (m == _mDisableGuard) return _disableScreenProtection();
    if (m == _mIsRecorded) return false;
    throw PlatformException(
      code: 'UNIMPLEMENTED',
      message: '${call.method} is not implemented on web',
    );
  }

  // ---------------------------------------------------------------------------
  // Memory method handler
  // ---------------------------------------------------------------------------

  static final Map<String, List<int>> _secureStore = {};

  static Future<dynamic> _handleMemoryCall(MethodCall call) async {
    final m = call.method;
    if (m == _mAllocate) {
      final args = call.arguments as Map<dynamic, dynamic>;
      final id = args['id'] as String;
      final data = (args['data'] as List<dynamic>).cast<int>();
      _secureStore[id] = List<int>.from(data);
      return true;
    }
    if (m == _mRead) {
      final args = call.arguments as Map<dynamic, dynamic>;
      final id = args['id'] as String;
      return _secureStore[id];
    }
    if (m == _mWipe) {
      final args = call.arguments as Map<dynamic, dynamic>;
      final id = args['id'] as String;
      final data = _secureStore[id];
      if (data != null) {
        for (var i = 0; i < data.length; i++) {
          data[i] = 0;
        }
        _secureStore.remove(id);
      }
      return true;
    }
    if (m == _mWipeAll) {
      for (final entry in _secureStore.values) {
        for (var i = 0; i < entry.length; i++) {
          entry[i] = 0;
        }
      }
      _secureStore.clear();
      return true;
    }
    throw PlatformException(
      code: 'UNIMPLEMENTED',
      message: '${call.method} is not implemented on web',
    );
  }

  // ---------------------------------------------------------------------------
  // Location method handler
  // ---------------------------------------------------------------------------

  static Future<dynamic> _handleLocationCall(MethodCall call) async {
    final m = call.method;
    if (m == _mFakeLoc) return _checkFakeLocationWeb();
    if (m == _mMockProv) return _checkGeolocationOverride();
    if (m == _mSpoofApps) {
      return <String, dynamic>{
        'detected': false,
        'detectedApps': <String>[],
      };
    }
    if (m == _mLocHooks) return _checkGeolocationHooks();
    if (m == _mGpsAnom) return 0.0;
    if (m == _mSensorFus) return 0.0;
    if (m == _mTempAnom) return 0.0;
    throw PlatformException(
      code: 'UNIMPLEMENTED',
      message: '${call.method} is not implemented on web',
    );
  }

  /// Full fake location check for web — combines available heuristics.
  static Map<String, dynamic> _checkFakeLocationWeb() {
    final scores = <String, double>{};
    final methods = <String>[];

    // Layer 1: Geolocation override detection
    final overrideDetected = _checkGeolocationOverride();
    scores['mockProvider'] = overrideDetected ? 0.8 : 0.0;
    if (overrideDetected) methods.add('mockProvider');

    // Layer 3: Geolocation API hook detection
    final hooksDetected = _checkGeolocationHooks();
    scores['locationHook'] = hooksDetected ? 0.7 : 0.0;
    if (hooksDetected) methods.add('locationHook');

    // Layers 2,4,5 not applicable on web
    scores['spoofingApp'] = 0.0;
    scores['gpsSignal'] = 0.0;
    scores['sensorFusion'] = 0.0;
    scores['temporalAnomaly'] = 0.0;

    // Layer 7: Aggregate
    var total = 0.0;
    var weight = 0.0;
    scores.forEach((k, v) {
      total += v;
      weight += 1.0;
    });
    final confidence = weight > 0 ? (total / weight) : 0.0;
    final triggered = scores.values.where((v) => v > 0.3).length;
    final amplifier = triggered >= 3 ? 1.5 : triggered >= 2 ? 1.3 : 1.0;
    final finalConfidence = (confidence * amplifier).clamp(0.0, 1.0);

    return <String, dynamic>{
      'isSpoofed': finalConfidence >= 0.5,
      'confidence': finalConfidence,
      'detectedMethods': methods,
      'layerScores': scores,
      'summary': finalConfidence >= 0.5
          ? 'Fake location detected (web)'
          : 'Location appears authentic',
    };
  }

  /// Check if Chrome DevTools geolocation override is active.
  static bool _checkGeolocationOverride() {
    try {
      // DevTools overrides set navigator.geolocation to a custom object
      // Check if getCurrentPosition has been replaced
      final result = _evalJs(
        'typeof navigator !== "undefined" && '
        'typeof navigator.geolocation !== "undefined" && '
        'typeof navigator.geolocation.getCurrentPosition === "function" && '
        'navigator.geolocation.getCurrentPosition.toString().indexOf("native code") === -1',
      );
      return result == true;
    } catch (_) {
      return false;
    }
  }

  /// Check if Geolocation API prototype has been tampered.
  static bool _checkGeolocationHooks() {
    try {
      // Check if Geolocation prototype methods are native
      final result = _evalJs(
        'typeof Geolocation !== "undefined" && '
        'typeof Geolocation.prototype.getCurrentPosition === "function" && '
        'Geolocation.prototype.getCurrentPosition.toString().indexOf("native code") === -1',
      );
      return result == true;
    } catch (_) {
      return false;
    }
  }

  // ===========================================================================
  // RASP Detection Implementations
  // ===========================================================================

  /// Detect DevTools open via outer/inner window size difference.
  ///
  /// When DevTools is docked, the outer window size stays the same but the
  /// inner (viewport) size shrinks. A difference > 160px on either axis
  /// strongly suggests DevTools is open.
  static bool _checkDebugger() {
    return _checkDevTools();
  }

  /// DevTools detection using window dimension heuristic.
  static bool _checkDevTools() {
    try {
      final window = web.window;
      final widthDiff = (window.outerWidth - window.innerWidth).abs();
      final heightDiff = (window.outerHeight - window.innerHeight).abs();

      // Threshold: DevTools panel is typically > 160px
      if (widthDiff > 160 || heightDiff > 160) {
        return true;
      }

      // Check for Firebug (legacy debugger)
      if (_hasGlobalProperty('__firebug')) {
        return true;
      }

      return false;
    } catch (_) {
      return false;
    }
  }

  /// Detect bot/automation/emulator environments.
  ///
  /// Checks `navigator.webdriver` (set by Selenium, Puppeteer, Playwright),
  /// headless browser indicators, and automation-specific properties.
  static bool _checkEmulator() {
    try {
      final navigator = web.window.navigator;

      // navigator.webdriver — set by WebDriver-based automation
      if (navigator.webdriver) {
        return true;
      }

      // User agent checks for headless browsers
      final ua = navigator.userAgent;
      if (ua.contains('HeadlessChrome') || ua.contains('PhantomJS')) {
        return true;
      }

      // Check for automation-injected global properties
      final automationKeys = [
        '_phantom',
        '__nightmare',
        '_selenium',
        'callPhantom',
        '__webdriver_evaluate',
        '__driver_evaluate',
        '__webdriver_unwrap',
        '__selenium_evaluate',
        '__fxdriver_evaluate',
        '__webdriver_script_fn',
        'domAutomation',
        'domAutomationController',
      ];

      for (final key in automationKeys) {
        if (_hasGlobalProperty(key)) return true;
      }

      // Check navigator.languages (headless often has empty array)
      if (navigator.languages.length == 0) {
        return true;
      }

      return false;
    } catch (_) {
      return false;
    }
  }

  /// Detect JavaScript hook/tampering of native browser functions.
  ///
  /// Checks if critical native functions have been overridden by comparing
  /// their toString() output — native functions return "[native code]".
  static bool _checkHooks() {
    try {
      final functionsToCheck = [
        'fetch',
        'XMLHttpRequest',
        'setTimeout',
        'setInterval',
        'Promise',
        'eval',
        'Function',
      ];

      for (final fn in functionsToCheck) {
        if (_isNativeFunctionTampered(fn)) return true;
      }

      // Check for nested object functions (JSON.parse, JSON.stringify)
      if (_isNestedFunctionTampered('JSON', 'parse')) return true;
      if (_isNestedFunctionTampered('JSON', 'stringify')) return true;

      // Check for Proxy-based interception globals
      if (_hasGlobalProperty('__hook__') ||
          _hasGlobalProperty('__interceptor__')) {
        return true;
      }

      return false;
    } catch (_) {
      return false;
    }
  }

  /// Detect script injection and DOM integrity issues.
  ///
  /// Checks for unexpected `<script>` tags from different origins.
  static bool _checkIntegrity() {
    try {
      final scripts = web.document.querySelectorAll('script[src]');
      final currentOrigin = web.window.location.origin;

      for (var i = 0; i < scripts.length; i++) {
        final script = scripts.item(i)! as web.HTMLScriptElement;
        final src = script.src;
        if (src.isNotEmpty &&
            !src.startsWith(currentOrigin) &&
            !src.startsWith('data:') &&
            !src.startsWith('blob:')) {
          return true;
        }
      }

      // Check for excessive inline scripts (Flutter apps have ~1-3)
      final inlineScripts = web.document.querySelectorAll('script:not([src])');
      if (inlineScripts.length > 5) {
        return true;
      }

      // Check for tampering globals
      if (_hasGlobalProperty('__tamper__') ||
          _hasGlobalProperty('__inject__')) {
        return true;
      }

      return false;
    } catch (_) {
      return false;
    }
  }

  /// Detect native API prototype tampering.
  ///
  /// Verifies that key browser API prototypes haven't been modified.
  static bool _checkSignature() {
    try {
      // Verify Function.prototype.bind is native
      if (_isNestedPrototypeTampered('Function', 'bind')) return true;

      // Verify Object.prototype.toString is native
      if (_isNestedPrototypeTampered('Object', 'toString')) return true;

      // Verify Array.prototype.push is native
      if (_isNestedPrototypeTampered('Array', 'push')) return true;

      return false;
    } catch (_) {
      return false;
    }
  }

  /// Detect active debugging via timing anomaly.
  ///
  /// A tight computation loop takes predictable time normally but
  /// significantly longer when a debugger is stepping or breakpoints are set.
  static bool _checkNativeDebug() {
    try {
      final sw = Stopwatch()..start();

      // Tight computation loop — predictable under normal execution
      var result = 0;
      for (var i = 0; i < 10000; i++) {
        result += i;
      }
      // Prevent dead-code elimination
      if (result < 0) _evalJs('void 0');

      sw.stop();

      // Under normal conditions < 5ms. With debugger stepping: much longer.
      if (sw.elapsedMilliseconds > 50) {
        return true;
      }

      return false;
    } catch (_) {
      return false;
    }
  }

  /// Detect network threats (proxy/VPN) via heuristics.
  ///
  /// Checks WebRTC availability (VPN/privacy extensions often block it)
  /// and proxy-related global properties.
  static bool _checkNetworkThreats() {
    try {
      // Check if WebRTC is blocked (VPN extensions and privacy tools block it)
      final hasRTC = _hasGlobalProperty('RTCPeerConnection') ||
          _hasGlobalProperty('webkitRTCPeerConnection') ||
          _hasGlobalProperty('mozRTCPeerConnection');

      if (!hasRTC) {
        return true;
      }

      // Check for proxy-related extension globals
      if (_hasGlobalProperty('__proxy__') ||
          _hasGlobalProperty('__vpn__')) {
        return true;
      }

      return false;
    } catch (_) {
      return false;
    }
  }

  // ===========================================================================
  // Screen Protection Implementation
  // ===========================================================================

  static web.HTMLStyleElement? _protectionStyle;

  /// Enable CSS-based screen protection.
  ///
  /// Uses CSS to prevent content from being easily captured:
  /// - `user-select: none` prevents text selection/copy
  /// - Print media query hides body
  /// - Disables right-click and print shortcut
  ///
  /// Note: This is best-effort. Determined attackers can bypass CSS protection.
  static bool _enableScreenProtection() {
    try {
      if (_protectionStyle != null) return true; // Already active

      _protectionStyle = web.document.createElement('style')
          as web.HTMLStyleElement;
      _protectionStyle!.textContent = '''
        .flutter-neo-shield-protected {
          -webkit-user-select: none !important;
          -moz-user-select: none !important;
          -ms-user-select: none !important;
          user-select: none !important;
          -webkit-touch-callout: none !important;
        }
        @media print {
          body { display: none !important; }
        }
      ''';
      web.document.head?.append(_protectionStyle!);

      // Apply protection class to body
      web.document.body?.classList.add('flutter-neo-shield-protected');

      // Disable right-click context menu
      web.document.addEventListener(
        'contextmenu',
        _onContextMenu.toJS,
      );

      // Disable print shortcut (Ctrl+P)
      web.document.addEventListener(
        'keydown',
        _onKeyDown.toJS,
      );

      _screenProtectionActive = true;
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Context menu handler — prevents right-click when protection is active.
  static void _onContextMenu(web.Event event) {
    if (_screenProtectionActive) {
      event.preventDefault();
    }
  }

  /// Keydown handler — blocks Ctrl+P print shortcut when protection is active.
  static void _onKeyDown(web.KeyboardEvent event) {
    if (_screenProtectionActive && event.ctrlKey && event.key == 'p') {
      event.preventDefault();
    }
  }

  /// Disable CSS-based screen protection.
  static bool _disableScreenProtection() {
    try {
      _protectionStyle?.remove();
      _protectionStyle = null;
      web.document.body?.classList.remove('flutter-neo-shield-protected');

      web.document.removeEventListener(
        'contextmenu',
        _onContextMenu.toJS,
      );
      web.document.removeEventListener(
        'keydown',
        _onKeyDown.toJS,
      );

      _screenProtectionActive = false;
      return true;
    } catch (_) {
      return false;
    }
  }

  // ===========================================================================
  // JS Interop Helpers (WASM-compatible)
  // ===========================================================================

  /// Detect if the page is embedded in an iframe (clickjacking).
  static bool _checkClickjacking() {
    try {
      final result = _evalJs(
        'window.self !== window.top',
      );
      return result == true;
    } catch (_) {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // New v2.0.0 channel handlers
  // ---------------------------------------------------------------------------

  static final Map<String, String> _webSecureStore = {};

  static Future<dynamic> _handleSecureStorageCall(MethodCall call) async {
    final args = call.arguments as Map<dynamic, dynamic>?;
    switch (call.method) {
      case 'writeSecure':
        final key = args?['key'] as String? ?? '';
        final value = args?['value'] as String? ?? '';
        _webSecureStore[key] = value;
        return true;
      case 'readSecure':
        return _webSecureStore[args?['key'] as String? ?? ''];
      case 'deleteSecure':
        _webSecureStore.remove(args?['key'] as String? ?? '');
        return true;
      case 'containsKeySecure':
        return _webSecureStore.containsKey(args?['key'] as String? ?? '');
      case 'wipeAllSecure':
        _webSecureStore.clear();
        return true;
      default:
        throw PlatformException(code: 'UNIMPLEMENTED', message: '${call.method} not implemented on web');
    }
  }

  static Future<dynamic> _handleBiometricCall(MethodCall call) async {
    // Biometric auth not available on web
    switch (call.method) {
      case 'checkBiometric':
        return <String, dynamic>{'available': false, 'types': <String>[], 'canAuth': false};
      case 'authenticate':
        return <String, dynamic>{'success': false, 'error': 'Biometric not available on web'};
      default:
        throw PlatformException(code: 'UNIMPLEMENTED', message: '${call.method} not implemented on web');
    }
  }

  static Future<dynamic> _handleDeviceBindingCall(MethodCall call) async {
    if (call.method == 'getDeviceFingerprint') {
      // Generate a browser-based fingerprint
      try {
        final result = _evalJs(
          '[navigator.userAgent, navigator.language, screen.width, screen.height, '
          'screen.colorDepth, new Date().getTimezoneOffset()].join("|")',
        );
        return result?.toString();
      } catch (_) {
        return null;
      }
    }
    throw PlatformException(code: 'UNIMPLEMENTED', message: '${call.method} not implemented on web');
  }

  /// Check if a property exists on the global `window` object.
  static bool _hasGlobalProperty(String name) {
    final result = _evalJs('typeof window["$name"] !== "undefined"');
    return result == true;
  }

  /// Check if a top-level function has been tampered (not native).
  static bool _isNativeFunctionTampered(String funcName) {
    final result = _evalJs(
      'typeof window["$funcName"] === "function" && '
      'window["$funcName"].toString().indexOf("native code") === -1',
    );
    return result == true;
  }

  /// Check if a nested function (e.g. JSON.parse) has been tampered.
  static bool _isNestedFunctionTampered(String obj, String method) {
    final result = _evalJs(
      'typeof window["$obj"] !== "undefined" && '
      'typeof window["$obj"]["$method"] === "function" && '
      'window["$obj"]["$method"].toString().indexOf("native code") === -1',
    );
    return result == true;
  }

  /// Check if a prototype method has been tampered.
  static bool _isNestedPrototypeTampered(String constructor, String method) {
    final result = _evalJs(
      'typeof window["$constructor"] !== "undefined" && '
      'typeof window["$constructor"].prototype["$method"] === "function" && '
      'window["$constructor"].prototype["$method"].toString()'
      '.indexOf("native code") === -1',
    );
    return result == true;
  }

  /// Evaluate a JavaScript expression and return the result.
  ///
  /// Uses `globalThis.eval()` via js_interop for WASM compatibility.
  static Object? _evalJs(String code) {
    try {
      return _jsEval(code.toJS).dartify();
    } catch (_) {
      return null;
    }
  }
}

/// Binding to globalThis.eval() for WASM-compatible JS evaluation.
@JS('eval')
external JSAny? _jsEval(JSString code);
