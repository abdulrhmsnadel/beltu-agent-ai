import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';

class CommandScreen extends StatefulWidget { const CommandScreen({super.key}); @override State<CommandScreen> createState() => _CommandScreenState(); }
class _CommandScreenState extends State<CommandScreen> with SingleTickerProviderStateMixin {
  late final TabController tabs = TabController(length: 2, vsync: this);
  final controller = TextEditingController();
  final approvalToken = TextEditingController();
  final conversationId = 'mobile-main';
  List<dynamic> messages = [];
  @override void initState() { super.initState(); _load(); }
  @override void dispose() { tabs.dispose(); controller.dispose(); approvalToken.dispose(); super.dispose(); }
  Future<void> _load() async { try { final x = await context.read<BeltuAppState>().api.chat(conversationId); if (mounted) setState(() => messages = x); } catch (_) {} }
  Future<void> _send() async { final text = controller.text.trim(); if (text.isEmpty) return; controller.clear(); await context.read<BeltuAppState>().api.sendChat(conversationId, text); await _load(); }
  Future<void> _approve(Map<String,dynamic> a) async { final token = await showDialog<String>(context: context, builder: (_) => AlertDialog(title: Text('Approve ${a['action_kind']}'), content: TextField(controller: approvalToken, obscureText: true, decoration: const InputDecoration(labelText: 'Approval token'), onSubmitted: (v) => Navigator.pop(context, v),), actions: [TextButton(onPressed: ()=>Navigator.pop(context), child: const Text('Cancel')), FilledButton(onPressed: ()=>Navigator.pop(context, approvalToken.text.trim()), child: const Text('Approve'))])); approvalToken.clear(); if (token != null && token!.isNotEmpty) { await context.read<BeltuAppState>().api.approve((a['id'] as num).toInt(), token!); await context.read<BeltuAppState>().refresh(); }}
  @override Widget build(BuildContext context) { final state = context.watch<BeltuAppState>(); return Column(children: [TabBar(controller: tabs, tabs: const [Tab(text:'Agent Chat'), Tab(text:'Approvals')]), Expanded(child: TabBarView(controller: tabs, children: [
    Column(children: [Expanded(child: ListView.builder(reverse: false, itemCount: messages.length, padding: const EdgeInsets.all(12), itemBuilder: (_,i){final m = messages[i] as Map<String,dynamic>; final mine = m['direction']=='inbound'; return Align(alignment: mine ? Alignment.centerRight : Alignment.centerLeft, child: Card(child: Padding(padding: const EdgeInsets.all(12), child: Text('${m['body']}'))));})), SafeArea(child: Row(children: [Expanded(child: TextField(controller: controller, minLines:1, maxLines:4, decoration: const InputDecoration(hintText:'Talk to BELTU…'))), IconButton(onPressed:_send, icon:const Icon(Icons.send))]))
    ]),
    RefreshIndicator(onRefresh:state.refresh, child:ListView.builder(padding:const EdgeInsets.all(12), itemCount:state.approvals.length, itemBuilder:(_,i){final a=state.approvals[i].raw; return Card(child:Padding(padding:const EdgeInsets.all(14), child:Column(crossAxisAlignment:CrossAxisAlignment.start, children:[Text('#${a['id']} · ${a['action_kind']}', style:const TextStyle(fontWeight:FontWeight.bold)), const SizedBox(height:6), Text('${a['reason'] ?? 'Approval required'}'), const SizedBox(height:8), Text('Expires: ${a['expires_at'] ?? '-'}', style:Theme.of(context).textTheme.bodySmall), const SizedBox(height:10), Row(children:[FilledButton.icon(onPressed:()=>_approve(a), icon:const Icon(Icons.check), label:const Text('Approve')), const SizedBox(width:8), OutlinedButton.icon(onPressed:()=>context.read<BeltuAppState>().api.reject((a['id'] as num).toInt()).then((_)=>context.read<BeltuAppState>().refresh()), icon:const Icon(Icons.close), label:const Text('Reject'))]))));}))
  ]))]); }
}
