import 'package:flutter/material.dart';
import '../services/api_client.dart';

class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key, required this.api});
  final BeltuApiClient api;

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final controller = TextEditingController();
  List<dynamic> messages = [];
  final conversationId = 'mobile-main';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final value = await widget.api.chat(conversationId);
      if (mounted) setState(() => messages = value);
    } catch (_) {}
  }

  Future<void> _send() async {
    final text = controller.text.trim();
    if (text.isEmpty) return;
    controller.clear();
    await widget.api.sendChat(conversationId, text);
    await _load();
  }

  @override
  Widget build(BuildContext context) => Column(
        children: [
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(12),
              itemCount: messages.length,
              itemBuilder: (context, index) {
                final m = messages[index] as Map<String, dynamic>;
                final mine = m['direction'] == 'inbound';
                return Align(
                  alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
                  child: Card(child: Padding(padding: const EdgeInsets.all(12), child: Text(m['body'] as String))),
                );
              },
            ),
          ),
          SafeArea(
            child: Row(children: [
              Expanded(child: TextField(controller: controller, decoration: const InputDecoration(hintText: 'Talk to BELTU Agent'))),
              IconButton(onPressed: _send, icon: const Icon(Icons.send)),
            ]),
          ),
        ],
      );
}
