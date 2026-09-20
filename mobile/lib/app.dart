import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'services/api_client.dart';
import 'state/app_state.dart';
import 'screens/login_screen.dart';
import 'screens/dashboard_screen.dart';
import 'screens/command_screen.dart';
import 'screens/activity_screen.dart';
import 'screens/files_screen.dart';
import 'screens/reports_screen.dart';

class BeltuApp extends StatelessWidget {
  const BeltuApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => BeltuAppState(BeltuApiClient())..restore(),
      child: const _AppShell(),
    );
  }
}

class _AppShell extends StatefulWidget {
  const _AppShell();

  @override
  State<_AppShell> createState() => _AppShellState();
}

class _AppShellState extends State<_AppShell> {
  int index = 0;

  @override
  Widget build(BuildContext context) {
    final state = context.watch<BeltuAppState>();
    final pages = const [
      DashboardScreen(),
      CommandScreen(),
      ActivityScreen(),
      FilesScreen(),
      ReportsScreen(),
    ];

    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'BELTU Command Center',
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorSchemeSeed: Colors.cyan,
        scaffoldBackgroundColor: const Color(0xFF081016),
        cardColor: const Color(0xFF101A20),
      ),
      home: state.authenticated
          ? Scaffold(
              appBar: AppBar(
                title: const Text('BELTU Command Center'),
                actions: [
                  IconButton(
                    onPressed: () => context.read<BeltuAppState>().logout(),
                    icon: const Icon(Icons.logout),
                    tooltip: 'Disconnect',
                  ),
                ],
              ),
              body: pages[index],
              bottomNavigationBar: NavigationBar(
                selectedIndex: index,
                onDestinationSelected: (value) => setState(() => index = value),
                destinations: const [
                  NavigationDestination(icon: Icon(Icons.dashboard_outlined), selectedIcon: Icon(Icons.dashboard), label: 'Dashboard'),
                  NavigationDestination(icon: Icon(Icons.forum_outlined), selectedIcon: Icon(Icons.forum), label: 'Command'),
                  NavigationDestination(icon: Icon(Icons.bolt_outlined), selectedIcon: Icon(Icons.bolt), label: 'Live'),
                  NavigationDestination(icon: Icon(Icons.folder_outlined), selectedIcon: Icon(Icons.folder), label: 'Files'),
                  NavigationDestination(icon: Icon(Icons.description_outlined), selectedIcon: Icon(Icons.description), label: 'Reports'),
                ],
              ),
            )
          : const LoginScreen(),
    );
  }
}
