import * as asn1js from "asn1js";
import { bufferToHexCodes } from "pvutils";
import TimeStampReq from "pkijs/src/TimeStampReq";
import MessageImprint from "pkijs/src/MessageImprint";
import AlgorithmIdentifier from "pkijs/src/AlgorithmIdentifier";
//*********************************************************************************
let tspReqBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created TSP request 
//*********************************************************************************
//region Auxiliary functions 
//*********************************************************************************
function formatPEM(pemString)
{
	const stringLength = pemString.length;
	let resultString = "";
	
	for(let i = 0, count = 0; i < stringLength; i++, count++)
	{
		if(count > 63)
		{
			resultString = `${resultString}\r\n`;
			count = 0;
		}
		
		resultString = resultString + pemString[i];
	}
	
	return resultString;
}
//*********************************************************************************
export function handleFileBrowse(evt)
{
	let tempReader = new FileReader();
	
	let currentFiles = evt.target.files;
	
	tempReader.onload =
		function(event)
		{
			tspReqBuffer = event.target.result;
			parseTSPReq();
		};
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Create TSP request  
//*********************************************************************************
export function createTSPReq(buffer)
{
	//region Initial variables 
	let sequence = Promise.resolve();
	
	let tspReqSimpl = new TimeStampReq();
	//endregion 
	
	//region Put static variables 
	const fictionBuffer = new ArrayBuffer(4);
	const fictionView = new Uint8Array(fictionBuffer);
	fictionView[0] = 0x7F;
	fictionView[1] = 0x01;
	fictionView[2] = 0x02;
	fictionView[3] = 0x03;
	
	tspReqSimpl.messageImprint = new MessageImprint({
		hashAlgorithm: new AlgorithmIdentifier({
			algorithmId: "1.3.14.3.2.26"
		}),
		hashedMessage: new asn1js.OctetString({ valueHex: fictionBuffer })
	});
	
	tspReqSimpl.reqPolicy = "1.1.1";
	tspReqSimpl.certReq = true;
	tspReqSimpl.nonce = new asn1js.Integer({ valueHex: fictionBuffer });
	//endregion 
	
	//region Encode TSP request and put on the Web page 
	
	//region Convert ArrayBuffer to String 
	let signedDataString = "";
	
	let tsp_req_schema = tspReqSimpl.toSchema();
	tspReqBuffer = tsp_req_schema.toBER(false);
	
	const view = new Uint8Array(tspReqBuffer);
	
	for(let i = 0; i < view.length; i++)
		signedDataString = signedDataString + String.fromCharCode(view[i]);
	//endregion 
	
	let result_string = "";
	
	result_string = result_string + "\r\n-----BEGIN TSP REQUEST-----\r\n";
	result_string = result_string + formatPEM(window.btoa(signedDataString));
	result_string = result_string + "\r\n-----END TSP REQUEST-----\r\n\r\n";
	
	document.getElementById("new_signed_data").innerHTML = result_string;
	
	parseTSPReq();
	
	alert("TSP request has created successfully!");
	//endregion   
}
//*********************************************************************************
//endregion 
//*********************************************************************************
//region Parse existing TSP request  
//*********************************************************************************
function parseTSPReq()
{
	//region Initial check 
	if(tspReqBuffer.byteLength === 0)
	{
		alert("Nothing to parse!");
		return;
	}
	//endregion 
	
	//region Initial activities 
	document.getElementById("tsp-req-extn-div").style.display = "none";
	
	let imprintTable = document.getElementById("tsp-req-imprint");
	while(imprintTable.rows.length > 1)
	{
		imprintTable.deleteRow(imprintTable.rows.length - 1);
	}
	
	let extensionTable = document.getElementById("tsp-req-extn-table");
	while(extensionTable.rows.length > 1)
	{
		extensionTable.deleteRow(extensionTable.rows.length - 1);
	}
	//endregion 
	
	//region Decode existing TSP request
	let asn1 = asn1js.fromBER(tspReqBuffer);
	let tspReqSimpl = new TimeStampReq({ schema: asn1.result });
	//endregion 
	
	//region Put information about message imprint 
	const dgstmap = {
		"1.3.14.3.2.26": "SHA-1",
		"2.16.840.1.101.3.4.2.1": "SHA-256",
		"2.16.840.1.101.3.4.2.2": "SHA-384",
		"2.16.840.1.101.3.4.2.3": "SHA-512"
	};
	
	let hashAlgorithm = dgstmap[tspReqSimpl.messageImprint.hashAlgorithm.algorithmId];
	if(typeof hashAlgorithm === "undefined")
		hashAlgorithm = tspReqSimpl.messageImprint.hashAlgorithm.algorithmId;
	
	let row = imprintTable.insertRow(imprintTable.rows.length);
	let cell0 = row.insertCell(0);
	cell0.innerHTML = hashAlgorithm;
	let cell1 = row.insertCell(1);
	cell1.innerHTML = bufferToHexCodes(tspReqSimpl.messageImprint.hashedMessage.valueBlock.valueHex);
	//endregion 
	
	//region Put information about policy 
	if("reqPolicy" in tspReqSimpl)
	{
		document.getElementById("tsp-req-policy").innerHTML = tspReqSimpl.reqPolicy;
		document.getElementById("tsp-req-pol").style.display = "block";
	}
	//endregion 
	
	//region Put information about nonce 
	if("nonce" in tspReqSimpl)
	{
		document.getElementById("tsp-req-nonce").innerHTML = bufferToHexCodes(tspReqSimpl.nonce.valueBlock.valueHex);
		document.getElementById("tsp-req-non").style.display = "block";
	}
	//endregion 
	
	//region Put information about existence of "certReq" flag
	if("certReq" in tspReqSimpl)
	{
		document.getElementById("tsp-req-cert-req").innerHTML = tspReqSimpl.certReq;
		document.getElementById("tsp-req-cert").style.display = "block";
	}
	//endregion 
	
	//region Put information about TST info extensions 
	if("extensions" in tspReqSimpl)
	{
		let extensionTable = document.getElementById("resp-extensions");
		
		for(let i = 0; i < tspReqSimpl.extensions.length; i++)
		{
			let row = extensionTable.insertRow(extensionTable.rows.length);
			let cell0 = row.insertCell(0);
			cell0.innerHTML = tspReqSimpl.extensions[i].extnID;
		}
		
		document.getElementById("tsp-req-extn-div").style.display = "block";
	}
	//endregion   
}
//*********************************************************************************
//endregion 
//*********************************************************************************
