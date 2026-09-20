import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});
  @override State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final user = TextEditingController(text: 'beltu');
  final password = TextEditingController();
  @override void dispose() { user.dispose(); password.dispose(); super.dispose(); }
  @override Widget build(BuildContext context) {
    final state = context.watch<BeltuAppState>();
    return Scaffold(body: Center(child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 460), child: Card(margin: const EdgeInsets.all(24), child: Padding(padding: const EdgeInsets.all(28), child: Column(mainAxisSize: MainAxisSize.min, children: [
      const Icon(Icons.shield_rounded, size: 64), const SizedBox(height: 16),
      Text('BELTU Command Center', style: Theme.of(context).textTheme.headlineSmall),
      const SizedBox(height: 8), const Text('Secure local control plane'), const SizedBox(height: 24),
      TextField(controller: user, decoration: const InputDecoration(labelText: 'Username', prefixIcon: Icon(Icons.person_outline))),
      const SizedBox(height: 12), TextField(controller: password, obscureText: true, decoration: const InputDecoration(labelText: 'Password', prefixIcon: Icon(Icons.lock_outline))),
      if (state.error != null) Padding(padding: const EdgeInsets.only(top: 12), child: Text(state.error!, style: const TextStyle(color: Colors.redAccent))),
      const SizedBox(height: 20), SizedBox(width: double.infinity, child: FilledButton.icon(onPressed: state.busy ? null : () => state.login(user.text.trim(), password.text), icon: const Icon(Icons.login), label: Text(state.busy ? 'Connecting…' : 'Connect'))),
    ])))));
  }
}
