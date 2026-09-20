import 'dart:io';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';
import 'package:provider/provider.dart';
import '../state/app_state.dart';

class ReportsScreen extends StatefulWidget { const ReportsScreen({super.key}); @override State<ReportsScreen> createState()=>_ReportsScreenState(); }
class _ReportsScreenState extends State<ReportsScreen>{ final scan=TextEditingController(); List<dynamic> reports=[];
 Future<void> load() async {final id=int.tryParse(scan.text.trim());if(id==null)return;try{final x=await context.read<BeltuAppState>().api.reports(id);if(mounted)setState(()=>reports=x);}catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('$e')));}}
 Future<void> download(Map<String,dynamic> item) async {final id=int.tryParse(scan.text.trim());if(id==null)return;final path='${item['relative_path']}';final bytes=await context.read<BeltuAppState>().api.downloadFile(id,path);final dir=await getApplicationDocumentsDirectory();final file=File('${dir.path}/${item['relative_path'].toString().split('/').last}');await file.writeAsBytes(bytes,flush:true);if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('Saved ${file.path}')));}
 @override void dispose(){scan.dispose();super.dispose();}
 @override Widget build(BuildContext context)=>Column(children:[Padding(padding:const EdgeInsets.all(12),child:Row(children:[Expanded(child:TextField(controller:scan,keyboardType:TextInputType.number,decoration:const InputDecoration(labelText:'Scan ID'))),IconButton(onPressed:load,icon:const Icon(Icons.refresh))])),Expanded(child:ListView(children:reports.map((e){final x=e as Map<String,dynamic>;return Card(child:ListTile(leading:const Icon(Icons.description),title:Text('${x['report_type']}'),subtitle:Text('${x['size_bytes']} bytes · ${x['relative_path']}'),trailing:IconButton(onPressed:()=>download(x),icon:const Icon(Icons.download))));}).toList()))]);}
