import 'dart:async';
import 'package:flutter/foundation.dart';
import '../models/app_models.dart';
import '../services/api_client.dart';

class BeltuAppState extends ChangeNotifier {
  BeltuAppState(this.api);
  final BeltuApiClient api;
  bool busy = false;
  bool authenticated = false;
  String? error;
  DashboardResources? resources;
  List<ScanItem> scans = [];
  List<ApprovalItem> approvals = [];
  List<Map<String, dynamic>> liveEvents = [];
  StreamSubscription? _eventsSub;

  Future<void> restore() async {
    authenticated = await api.isAuthenticated();
    notifyListeners();
    if (authenticated) await refresh();
  }

  Future<void> login(String user, String password) async {
    busy = true;
    error = null;
    notifyListeners();
    try {
      await api.login(user, password);
      authenticated = true;
      await refresh();
      _connectEvents();
    } catch (e) {
      error = '$e';
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  Future<void> logout() async {
    await _eventsSub?.cancel();
    await api.logout();
    authenticated = false;
    notifyListeners();
  }

  Future<void> refresh() async {
    if (!authenticated) return;
    busy = true;
    error = null;
    notifyListeners();
    try {
      final results = await Future.wait([api.resources(), api.scans(), api.approvals()]);
      resources = DashboardResources(raw: results[0] as Map<String, dynamic>);
      scans = ((results[1] as List).cast<Map>().map((x) => ScanItem(x.cast<String, dynamic>())).toList());
      approvals = ((results[2] as List).cast<Map>().map((x) => ApprovalItem(x.cast<String, dynamic>())).toList());
    } catch (e) {
      error = '$e';
    } finally {
      busy = false;
      notifyListeners();
    }
  }

  void _connectEvents() {
    _eventsSub?.cancel();
    _eventsSub = api.liveEvents().listen((event) {
      liveEvents.insert(0, event);
      if (liveEvents.length > 120) liveEvents.removeLast();
      notifyListeners();
      refresh();
    }, onError: (_) {
      // The UI remains usable; a later refresh or screen restart reconnects.
    });
  }
}
