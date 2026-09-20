import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';

class ActivityScreen extends StatelessWidget { const ActivityScreen({super.key}); @override Widget build(BuildContext context) { final events=context.watch<BeltuAppState>().liveEvents; return ListView.builder(itemCount:events.length,itemBuilder:(_,i){final e=events[i];return ListTile(leading:const Icon(Icons.bolt),title:Text('${e['type']??'event'}'),subtitle:Text('${e['payload']??{}}'));}); } }
