import 'package:flutter/material.dart';
import 'package:flutter_neo_shield/flutter_neo_shield.dart';

import 'screens/clipboard_shield_demo.dart';
import 'screens/log_shield_demo.dart';
import 'screens/memory_shield_demo.dart';
import 'screens/string_shield_demo.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  FlutterNeoShield.init(
    config: const ShieldConfig(enableReporting: true),
    logConfig: const LogShieldConfig(silentInRelease: true),
    clipboardConfig: const ClipboardShieldConfig(
      defaultExpiry: Duration(seconds: 30),
    ),
    memoryConfig: const MemoryShieldConfig(enablePlatformWipe: false),
    stringShieldConfig: const StringShieldConfig(
      enableCache: true,
      enableStats: true,
    ),
  );

  runApp(const FlutterNeoShieldDemoApp());
}

/// The flutter_neo_shield demo application.
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

/// Home page with bottom navigation for the four demo screens.
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
  ];

  final _titles = const [
    'Log Shield',
    'Clipboard Shield',
    'Memory Shield',
    'String Shield',
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
            label: 'Log Shield',
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
        ],
      ),
    );
  }
}
