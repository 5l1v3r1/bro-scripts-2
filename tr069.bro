@load base/protocols/http
@load base/frameworks/files

redef record HTTP::Info += {
	post_body: string &log &optional;
};

redef record Files::Info += {
	post_body: string &log &optional;
};

module TR_069;

const rpc_methods: set [string] = {
		"GetRPCMethods", 
		"SetParameterValues", 
		"GetParameterValues", 
		"GetParameterNames", 
		"SetParameterAttributes", 
		"GetParameterAttributes", 
		"AddObject", 
		"DeleteObject", 
		"Download", 
		"Reboot", 
		"GetQueuedTransfers", 
		"ScheduleInform", 
		"SetVouchers", 
		"GetOptions", 
		"Upload", 
		"FactoryReset", 
		"GetAllQueuedTransfers", 
		"ScheduleDownload", 
		"CancelTransfer", 
		"ChangeDUState", 
		"Inform", 
		"TransferComplete", 
		"AutonomousTransferComplete", 
		"Kicked", 
		"RequestDownload", 
		"DUStateChangeComplete", 
		"AutonomousDUStateChangeComplete", 
		"GetRPCMethodsResponse", 
		"SetParameterValuesResponse", 
		"GetParameterValuesResponse", 
		"GetParameterNamesResponse", 
		"SetParameterAttributesResponse", 
		"GetParameterAttributesResponse", 
		"AddObjectResponse", 
		"DeleteObjectResponse", 
		"DownloadResponse", 
		"RebootResponse", 
		"GetQueuedTransfersResponse", 
		"ScheduleInformResponse", 
		"SetVouchersResponse", 
		"GetOptionsResponse", 
		"UploadResponse", 
		"FactoryResetResponse", 
		"GetAllQueuedTransfersResponse", 
		"ScheduleDownloadResponse", 
		"CancelTransferResponse", 
		"ChangeDUStateResponse", 
		"InformResponse", 
		"TransferCompleteResponse", 
		"AutonomousTransferCompleteResponse", 
		"KickedResponse", 
		"RequestDownloadResponse", 
		"DUStateChangeCompleteResponse", 
		"AutonomousDUStateChangeCompleteResponse"
};

export {
    redef enum Log::ID += { LOG };

    type Info: record {
		ts: time        &log;
		id: conn_id     &log &optional;
		service: string &log &optional &default="TR069";
		rpc_method: string &log &optional;
		filename: string &optional &log;
		user_agent: string &log &optional;
		host: string &log &optional;
		http_method: string &log &optional;
		uri: string &log &optional;
		password: string &log &optional;
		username: string &log &optional;
		status_code: count &log &optional;
		status_msg: string &log &optional;
    };
}

redef record connection += {
	tr_069: Info &optional;
};

global mime_to_ext: table[string] of string = {
	["application/soap+xml"] = "xml"
};

function save_xml(data: string, file_id: string): string
{
	local regex: pattern = /<SOAP-ENV:Body>(\x0A|\x0D)*<cwmp:[A-Za-z0-9]+/;
	local x = find_all(data, regex);
	
	if (|x| > 0) {
		for (i in x) {
			local soap_com = split_string(i, /:/)[2];
			if (soap_com in rpc_methods){
				local soap_file_name = fmt("%s-%s-%s%s", "TR069", soap_com, file_id ,".xml");
				local local_file = open(soap_file_name);
				write_file(local_file, data);
				close(local_file);
				return soap_file_name;
			}
			else{
				return "non_tr069";
			}
		}
	}
	else{
		return "non_tr069";
	}
}

event log_post_bodies(f: fa_file,  data: string)
{
	if (!f$info?$post_body) {
		f$info$post_body = "";
	}

	for ( cid in f$conns )
	{
		local c: connection = f$conns[cid];
		if (|data| <= 0) {
			local filename: string = save_xml(f$info$post_body, f$id);
			if (filename!="non_tr069") {
				local tr069_tmp = TR_069::Info($ts=network_time(), $service = "TR069", $id = cid, $rpc_method = split_string(filename, /-/)[1], $filename=filename, $user_agent=c$http$user_agent, $host = c$http$host, $http_method = c$http$method, $uri = c$http$uri);
				Log::write(TR_069::LOG, tr069_tmp);
			}
		}
		else {
			f$info$post_body =  f$info$post_body + data;
		}
	}
}

event file_sniff(f: fa_file, meta:fa_metadata)
{
	if ( f?$http && meta?$mime_type && meta$mime_type in mime_to_ext ) {
		Files::add_analyzer(f, Files::ANALYZER_DATA_EVENT, [$stream_event=log_post_bodies]);
	}
}

event bro_init()
{
	print "Bro init!!!!";

	Log::create_stream(TR_069::LOG, [$columns=Info, $path="tr069"]);
	Log::remove_filter(Files::LOG, "default");
	local filter: Log::Filter = [$name="orig-only", $exclude=set("post_body")];
	Log::add_filter(Files::LOG, filter);
}

event bro_done()
{
	print "Bro done!!!!";
}
