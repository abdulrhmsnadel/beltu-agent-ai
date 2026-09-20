import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';
import '../widgets/metric_card.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});
  @override Widget build(BuildContext context) {
    final state = context.watch<BeltuAppState>();
    final r = state.resources;
    final gpu = r?.gpu; final ft = r?.freetoken;
    return RefreshIndicator(onRefresh: state.refresh, child: ListView(padding: const EdgeInsets.all(16), children: [
      Row(children: [Expanded(child: Text('Command Center', style: Theme.of(context).textTheme.headlineSmall)), IconButton(onPressed: state.busy ? null : state.refresh, icon: const Icon(Icons.refresh))]),
      const SizedBox(height: 6), Text('Local BELTU operations', style: Theme.of(context).textTheme.bodyMedium), const SizedBox(height: 16),
      GridView.count(crossAxisCount: MediaQuery.sizeOf(context).width > 700 ? 4 : 2, crossAxisSpacing: 12, mainAxisSpacing: 12, childAspectRatio: 1.55, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(), children: [
        MetricCard(title: 'BELTU CPU', value: '${r?.beltu['cpu_percent'] ?? 0}% ', subtitle: '30% budget', icon: Icons.memory),
        MetricCard(title: 'BELTU RAM', value: '${r?.beltu['memory_percent'] ?? 0}%', subtitle: 'resident set', icon: Icons.storage_rounded),
        MetricCard(title: 'GPU VRAM', value: gpu == null ? 'N/A' : '${gpu['used_percent']}%', subtitle: gpu == null ? 'no NVIDIA telemetry' : '${gpu['name']}', icon: Icons.developer_board),
        MetricCard(title: 'FreeToken', value: ft == null ? 'OFFLINE' : (ft['reachable'] == true ? 'ONLINE' : 'OFFLINE'), subtitle: 'model ${ft?['model'] ?? '-'}', icon: Icons.psychology),
      ]),
      const SizedBox(height: 20),
      Text('Active scans', style: Theme.of(context).textTheme.titleLarge), const SizedBox(height: 8),
      ...state.scans.take(8).map((scan) => Card(child: ListTile(leading: CircleAvatar(child: Icon(scan.status == 'running' ? Icons.play_arrow : Icons.flag_outlined)), title: Text('#${scan.id} · ${scan.target}'), subtitle: Text(scan.status), trailing: const Icon(Icons.chevron_right)))),
      const SizedBox(height: 16), Text('Latest live events', style: Theme.of(context).textTheme.titleLarge), const SizedBox(height: 8),
      ...state.liveEvents.take(8).map((e) => ListTile(leading: const Icon(Icons.bolt), title: Text('${e['type'] ?? 'event'}'), subtitle: Text('${e['payload'] ?? {}}'))),
    ]));
  }
}
