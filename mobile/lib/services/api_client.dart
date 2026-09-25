import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';

class BeltuApiClient {
  BeltuApiClient({String? baseUrl})
      : baseUrl = (baseUrl ?? const String.fromEnvironment('BELTU_BASE_URL', defaultValue: 'http://127.0.0.1:8765')).replaceAll(RegExp(r'/+$'), '');
  final String baseUrl;
  final FlutterSecureStorage storage = const FlutterSecureStorage();

  Future<void> login(String username, String password) async {
    final response = await http.post(
      Uri.parse('$baseUrl/v1/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'username': username, 'password': password}),
    );
    _ensureOk(response);
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    await storage.write(key: 'beltu_access_token', value: body['access_token'] as String);
    await storage.write(key: 'beltu_username', value: username);
  }

  Future<void> logout() => storage.delete(key: 'beltu_access_token');

  Future<bool> isAuthenticated() async => (await storage.read(key: 'beltu_access_token'))?.isNotEmpty == true;

  Future<Map<String, String>> _headers() async {
    final token = await storage.read(key: 'beltu_access_token');
    if (token == null || token.isEmpty) throw Exception('Not authenticated');
    return {'Authorization': 'Bearer $token', 'Content-Type': 'application/json'};
  }

  Future<List<dynamic>> scans() async {
    final r = await http.get(Uri.parse('$baseUrl/v1/scans'), headers: await _headers());
    _ensureOk(r);
    return (jsonDecode(r.body)['items'] as List<dynamic>);
  }

  Future<Map<String, dynamic>> resources() async {
    final r = await http.get(Uri.parse('$baseUrl/v1/system/resources'), headers: await _headers());
    _ensureOk(r);
    return (jsonDecode(r.body) as Map<String, dynamic>);
  }

  Future<Map<String, dynamic>> activity(int scanId) async {
    final r = await http.get(Uri.parse('$baseUrl/v1/scans/$scanId/activity'), headers: await _headers());
    _ensureOk(r);
    return (jsonDecode(r.body) as Map<String, dynamic>);
  }

  Future<List<dynamic>> findings(int scanId) async {
    final r = await http.get(Uri.parse('$baseUrl/v1/scans/$scanId/findings'), headers: await _headers());
    _ensureOk(r);
    return jsonDecode(r.body)['items'] as List<dynamic>;
  }

  Future<List<dynamic>> chat(String conversationId) async {
    final r = await http.get(Uri.parse('$baseUrl/v1/chat/${Uri.encodeComponent(conversationId)}'), headers: await _headers());
    _ensureOk(r);
    return jsonDecode(r.body)['items'] as List<dynamic>;
  }

  Future<void> sendChat(String conversationId, String body) async {
    final r = await http.post(
      Uri.parse('$baseUrl/v1/chat/messages'),
      headers: await _headers(),
      body: jsonEncode({'conversation_id': conversationId, 'body': body}),
    );
    _ensureOk(r);
  }

  Future<List<dynamic>> approvals() async {
    final r = await http.get(Uri.parse('$baseUrl/v1/approvals'), headers: await _headers());
    _ensureOk(r);
    return jsonDecode(r.body)['items'] as List<dynamic>;
  }

  Future<void> approve(int approvalId, String token) async {
    final uri = Uri.parse('$baseUrl/v1/approvals/$approvalId/approve');
    final r = await http.post(
      uri,
      headers: await _headers(),
      body: jsonEncode({'token': token}),
    );
    _ensureOk(r);
  }

  Future<void> reject(int approvalId) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/approvals/$approvalId/reject'), headers: await _headers());
    _ensureOk(r);
  }

  Future<List<dynamic>> files(int scanId, [String path = '']) async {
    final uri = Uri.parse('$baseUrl/v1/scans/$scanId/files').replace(queryParameters: {'path': path});
    final r = await http.get(uri, headers: await _headers());
    _ensureOk(r);
    return jsonDecode(r.body)['items'] as List<dynamic>;
  }

  Future<String> readTextFile(int scanId, String path) async {
    final uri = Uri.parse('$baseUrl/v1/scans/$scanId/files/content').replace(queryParameters: {'path': path});
    final r = await http.get(uri, headers: await _headers());
    _ensureOk(r);
    return utf8.decode(r.bodyBytes);
  }

  Future<Uint8List> downloadFile(int scanId, String path) async {
    final uri = Uri.parse('$baseUrl/v1/scans/$scanId/files/download').replace(queryParameters: {'path': path});
    final r = await http.get(uri, headers: await _headers());
    _ensureOk(r);
    return r.bodyBytes;
  }

  Future<List<dynamic>> reports(int scanId) async {
    final r = await http.get(Uri.parse('$baseUrl/v1/scans/$scanId/reports'), headers: await _headers());
    _ensureOk(r);
    return jsonDecode(r.body)['items'] as List<dynamic>;
  }

  Stream<Map<String, dynamic>> liveEvents() async* {
    final token = await storage.read(key: 'beltu_access_token');
    if (token == null || token.isEmpty) throw Exception('Not authenticated');
    final scheme = baseUrl.startsWith('https://') ? 'wss://' : 'ws://';
    final authority = baseUrl.replaceFirst(RegExp(r'^https?://'), '');
    final channel = WebSocketChannel.connect(Uri.parse('$scheme$authority/v1/ws/events'));
    channel.sink.add(jsonEncode({'token': token}));
    try {
      await for (final message in channel.stream) {
        if (message is String) yield jsonDecode(message) as Map<String, dynamic>;
      }
    } finally {
      await channel.sink.close();
    }
  }

  void _ensureOk(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw Exception('BELTU API ${response.statusCode}: ${response.body}');
    }
  }
}
