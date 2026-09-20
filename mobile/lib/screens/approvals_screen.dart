import 'package:flutter/material.dart';
import '../services/api_client.dart';

class ApprovalsScreen extends StatefulWidget {
  const ApprovalsScreen({super.key, required this.api});
  final BeltuApiClient api;
  @override State<ApprovalsScreen> createState() => _ApprovalsScreenState();
}
class _ApprovalsScreenState extends State<ApprovalsScreen> {
  List<dynamic> items=[]; final token=TextEditingController();
  @override void initState(){super.initState(); _load();}
  Future<void> _load() async { try { final x=await widget.api.approvals(); if(mounted)setState(()=>items=x); } catch(_){} }
  Future<void> _approve(Map<String,dynamic> x) async {
    final value=await showDialog<String>(context:context,builder:(_)=>AlertDialog(title:const Text('Approval token'),content:TextField(controller:token,obscureText:true),actions:[TextButton(onPressed:()=>Navigator.pop(context),child:const Text('Cancel')),FilledButton(onPressed:()=>Navigator.pop(context,token.text.trim()),child:const Text('Approve'))]));
    token.clear(); if(value==null||value!.isEmpty)return; await widget.api.approve(x['id'] as int,value!); await _load();
  }
  Future<void> _reject(Map<String,dynamic> x) async { await widget.api.reject(x['id'] as int); await _load(); }
  @override Widget build(BuildContext context)=>RefreshIndicator(onRefresh:_load,child:ListView.builder(itemCount:items.length,itemBuilder:(_,i){final x=items[i] as Map<String,dynamic>;return Card(child:ListTile(title:Text('Approval #${x['id']} · ${x['action_kind']}'),subtitle:Text('Scan #${x['scan_id']}\nExpires ${x['expires_at']}'),isThreeLine:true,trailing:Wrap(children:[IconButton(onPressed:()=>_approve(x),icon:const Icon(Icons.check_circle_outline)),IconButton(onPressed:()=>_reject(x),icon:const Icon(Icons.cancel_outlined))])));}));
}
