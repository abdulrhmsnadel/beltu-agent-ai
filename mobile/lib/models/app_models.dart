class DashboardResources {
  DashboardResources({required this.raw});
  final Map<String, dynamic> raw;
  Map<String, dynamic> get beltu => (raw['beltu'] as Map?)?.cast<String, dynamic>() ?? {};
  Map<String, dynamic> get host => (raw['host'] as Map?)?.cast<String, dynamic>() ?? {};
  Map<String, dynamic>? get gpu => (raw['gpu'] as Map?)?.cast<String, dynamic>();
  Map<String, dynamic>? get freetoken => (raw['freetoken'] as Map?)?.cast<String, dynamic>();
  List<dynamic> get toolLimits => ((raw['tool_limits'] as Map?)?.values ?? const []).toList();
  int get processCapacity => (raw['adaptive_process_capacity'] as num?)?.toInt() ?? 0;
}

class ScanItem {
  ScanItem(this.raw);
  final Map<String, dynamic> raw;
  int get id => (raw['id'] as num).toInt();
  String get target => '${raw['target'] ?? ''}';
  String get status => '${raw['status'] ?? ''}';
}

class ApprovalItem {
  ApprovalItem(this.raw);
  final Map<String, dynamic> raw;
  int get id => (raw['id'] as num).toInt();
  int get scanId => (raw['scan_id'] as num).toInt();
  String get actionKind => '${raw['action_kind'] ?? ''}';
  String get reason => '${raw['reason'] ?? ''}';
  String get expiresAt => '${raw['expires_at'] ?? ''}';
}
