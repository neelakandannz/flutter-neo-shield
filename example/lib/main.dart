import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

import 'screens/clipboard_shield_demo.dart';
import 'screens/log_shield_demo.dart';
import 'screens/memory_shield_demo.dart';
import 'screens/string_shield_demo.dart';
import 'screens/rasp_shield_demo.dart';
import 'screens/screen_shield_demo.dart';
import 'screens/location_shield_demo.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize all shield modules with sensible defaults.
  // Each module is optional — only pass configs for what you need.
  FlutterNeoShield.init(
    // Core PII detection engine — tracks detection statistics.
    config: const ShieldConfig(enableReporting: true),

    // Log Shield — hides PII from debug console and crash reporters.
    // silentInRelease: no logs at all in production builds.
    logConfig: const LogShieldConfig(silentInRelease: true),

    // Clipboard Shield — auto-clears clipboard after 30 seconds.
    // Prevents sensitive data (API keys, passwords) from lingering.
    clipboardConfig: const ClipboardShieldConfig(
      defaultExpiry: Duration(seconds: 30),
    ),

    // Memory Shield — overwrites secret bytes with zeros on dispose.
    // enablePlatformWipe: false = use Dart-side wipe only (no native channel).
    memoryConfig: const MemoryShieldConfig(enablePlatformWipe: false),

    // String Shield — decrypts obfuscated strings at runtime.
    // enableCache: true = cache decrypted values (faster, slightly less secure).
    // enableStats: true = track how many times each string is accessed.
    stringShieldConfig: const StringShieldConfig(
      enableCache: true,
      enableStats: true,
    ),

    // Screen Shield — prevents screenshots and screen recording.
    //
    // How it works:
    //   Android: Sets FLAG_SECURE on the Activity window. The OS renders a
    //            BLACK screen for all capture methods (screenshots, recording,
    //            Chromecast, adb screencap, and the app switcher thumbnail).
    //
    //   iOS:     Uses a secure UITextField layer trick. The OS blanks the
    //            content during capture. Also adds a blur overlay in the
    //            app switcher (recent apps). Fires events when screenshots
    //            are taken or screen recording starts/stops.
    //
    // enableOnInit: true = protection starts immediately when the app launches.
    // Set to false if you only want to protect specific screens (use
    // ScreenShieldScope widget or call enableProtection() manually).
    screenConfig: const ScreenShieldConfig(
      enableOnInit: false, // We'll toggle it in the demo screen manually
      blockScreenshots: true,
      blockRecording: true,
      guardAppSwitcher: true,
      detectScreenshots: true,
      detectRecording: true,
    ),
  );

  runApp(const FlutterNeoShieldDemoApp());
}

/// The flutter_neo_shield demo application.
///
/// Showcases all 7 shield modules with interactive demos:
/// - Log Shield: sanitized logging with PII detection
/// - Clipboard Shield: auto-clearing clipboard with countdown
/// - Memory Shield: SecureString/SecureBytes lifecycle management
/// - String Shield: compile-time obfuscation with runtime stats
/// - RASP Shield: full security scan (root, debugger, emulator, etc.)
/// - Screen Shield: screenshot/recording prevention with live toggle
/// - Location Shield: 7-layer fake GPS/mock location detection
class FlutterNeoShieldDemoApp extends StatelessWidget {
  /// Creates the demo app.
  const FlutterNeoShieldDemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'flutter_neo_shield Demo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        useMaterial3: true,
        brightness: Brightness.light,
      ),
      darkTheme: ThemeData(
        colorSchemeSeed: Colors.indigo,
        useMaterial3: true,
        brightness: Brightness.dark,
      ),
      home: const HomePage(),
    );
  }
}

/// Home page with bottom navigation for the six demo screens.
class HomePage extends StatefulWidget {
  /// Creates the [HomePage].
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  int _currentIndex = 0;

  final _screens = const [
    LogShieldDemo(),
    ClipboardShieldDemo(),
    MemoryShieldDemo(),
    StringShieldDemo(),
    RaspShieldDemo(),
    ScreenShieldDemo(),
    LocationShieldDemo(),
  ];

  final _titles = const [
    'Log Shield',
    'Clipboard Shield',
    'Memory Shield',
    'String Shield',
    'RASP Shield',
    'Screen Shield',
    'Location Shield',
  ];

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('${_titles[_currentIndex]} Demo'),
        centerTitle: true,
      ),
      body: _screens[_currentIndex],
      bottomNavigationBar: NavigationBar(
        selectedIndex: _currentIndex,
        onDestinationSelected: (index) {
          setState(() => _currentIndex = index);
        },
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.description_outlined),
            selectedIcon: Icon(Icons.description),
            label: 'Log',
          ),
          NavigationDestination(
            icon: Icon(Icons.content_paste_outlined),
            selectedIcon: Icon(Icons.content_paste),
            label: 'Clipboard',
          ),
          NavigationDestination(
            icon: Icon(Icons.memory_outlined),
            selectedIcon: Icon(Icons.memory),
            label: 'Memory',
          ),
          NavigationDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: 'String',
          ),
          NavigationDestination(
            icon: Icon(Icons.gpp_good_outlined),
            selectedIcon: Icon(Icons.gpp_good),
            label: 'RASP',
          ),
          NavigationDestination(
            icon: Icon(Icons.screenshot_monitor_outlined),
            selectedIcon: Icon(Icons.screenshot_monitor),
            label: 'Screen',
          ),
          NavigationDestination(
            icon: Icon(Icons.location_off_outlined),
            selectedIcon: Icon(Icons.location_off),
            label: 'Location',
          ),
        ],
      ),
    );
  }
}
