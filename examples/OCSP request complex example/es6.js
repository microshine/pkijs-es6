import * as asn1js from "asn1js";
import { bufferToHexCodes } from "pvutils";
import Certificate from "pkijs/src/Certificate";
import OCSPRequest from "pkijs/src/OCSPRequest";
import GeneralName from "pkijs/src/GeneralName";
import RelativeDistinguishedNames from "pkijs/src/RelativeDistinguishedNames";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import Request from "pkijs/src/Request";
import CertID from "pkijs/src/CertID";
import AlgorithmIdentifier from "pkijs/src/AlgorithmIdentifier";
import Extension from "pkijs/src/Extension";
//*********************************************************************************
let ocspReqBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created OCSP request
let issuerCertificate = null;
let issuerPublicKey = null;
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
	let temp_reader = new FileReader();
	
	let current_files = evt.target.files;
	
	temp_reader.onload =
		function(event)
		{
			ocspReqBuffer = event.target.result;
			parseOCSPReq();
		};
	
	temp_reader.readAsArrayBuffer(current_files[0]);
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Create OCSP request  
//*********************************************************************************
export function createOCSPReq(buffer)
{
	//region Initial variables 
	let sequence = Promise.resolve();
	
	let ocspReqSimpl = new OCSPRequest();
	//endregion 
	
	//region Put static variables 
	ocspReqSimpl.tbsRequest.requestorName = new GeneralName({
		type: 4,
		value: new RelativeDistinguishedNames({
			typesAndValues: [
				new AttributeTypeAndValue({
					type: "2.5.4.6", // Country name
					value: new asn1js.PrintableString({ value: "RU" })
				}),
				new AttributeTypeAndValue({
					type: "2.5.4.3", // Common name
					value: new asn1js.BmpString({ value: "Test" })
				})
			]
		})
	});
	
	const fictionBuffer = new ArrayBuffer(4);
	const fictionView = new Uint8Array(fictionBuffer);
	fictionView[0] = 0x7F;
	fictionView[1] = 0x01;
	fictionView[2] = 0x02;
	fictionView[3] = 0x03;
	
	ocspReqSimpl.tbsRequest.requestList = [new Request({
		reqCert: new CertID({
			hashAlgorithm: new AlgorithmIdentifier({
				algorithmId: "1.3.14.3.2.26"
			}),
			issuerNameHash: new asn1js.OctetString({ valueHex: fictionBuffer }),
			issuerKeyHash: new asn1js.OctetString({ valueHex: fictionBuffer }),
			serialNumber: new asn1js.Integer({ valueHex: fictionBuffer })
		})
	})];
	
	ocspReqSimpl.tbsRequest.requestExtensions = [
		new Extension({
			extnID: "1.3.6.1.5.5.7.48.1.2", // ocspNonce
			extnValue: (new asn1js.OctetString({ valueHex: fictionBuffer })).toBER(false)
		})
	];
	//endregion 
	
	//region Encode OCSP request and put on the Web page 
	
	//region Convert ArrayBuffer to String 
	let signedDataString = "";
	
	let ocspReqSchema = ocspReqSimpl.toSchema(true);
	ocspReqBuffer = ocspReqSchema.toBER(false);
	
	const view = new Uint8Array(ocspReqBuffer);
	
	for(let i = 0; i < view.length; i++)
		signedDataString = signedDataString + String.fromCharCode(view[i]);
	//endregion 
	
	let result_string = "";
	
	result_string = result_string + "\r\n-----BEGIN OCSP REQUEST-----\r\n";
	result_string = result_string + formatPEM(window.btoa(signedDataString));
	result_string = result_string + "\r\n-----END OCSP REQUEST-----\r\n\r\n";
	
	document.getElementById("new_signed_data").innerHTML = result_string;
	
	parseOCSPReq();
	
	alert("OCSP request has created successfully!");
	//endregion   
}
//*********************************************************************************
//endregion 
//*********************************************************************************
//region Parse existing OCSP request  
//*********************************************************************************
function parseOCSPReq()
{
	//region Initial check 
	if(ocspReqBuffer.byteLength === 0)
	{
		alert("Nothing to parse!");
		return;
	}
	//endregion 
	
	//region Initial activities 
	document.getElementById("ocsp-req-extn-div").style.display = "none";
	
	const requestsTable = document.getElementById("ocsp-req-requests");
	while(requestsTable.rows.length > 1)
		requestsTable.deleteRow(requestsTable.rows.length - 1);
	
	const extensionTable = document.getElementById("ocsp-req-extn-table");
	while(extensionTable.rows.length > 1)
		extensionTable.deleteRow(extensionTable.rows.length - 1);
	
	const requestorTable = document.getElementById("ocsp-req-name");
	while(requestorTable.rows.length > 1)
		requestorTable.deleteRow(requestorTable.rows.length - 1);
	//endregion 
	
	//region Decode existing OCSP request
	let asn1 = asn1js.fromBER(ocspReqBuffer);
	let ocspReqSimpl = new OCSPRequest({ schema: asn1.result });
	//endregion 
	
	//region Put information about OCSP request requestor 
	if("requestorName" in ocspReqSimpl.tbsRequest)
	{
		switch(ocspReqSimpl.tbsRequest.requestorName.type)
		{
			case 1: // rfc822Name
			case 2: // dNSName
			case 6: // uniformResourceIdentifier
				document.getElementById("ocsp-req-name-simpl").innerHTML = ocspReqSimpl.tbsRequest.requestorName.value.valueBlock.value;
				document.getElementById("ocsp-req-nm-simpl").style.display = "block";
				break;
			case 7: // iPAddress
				{
					const view = new Uint8Array(ocspReqSimpl.tbsRequest.requestorName.value.valueBlock.valueHex);
					
					document.getElementById("ocsp-req-name-simpl").innerHTML = view[0].toString() + "." + view[1].toString() + "." + view[2].toString() + "." + view[3].toString();
					document.getElementById("ocsp-req-nm-simpl").style.display = "block";
				}
				break;
			case 3: // x400Address
			case 5: // ediPartyName
				document.getElementById("ocsp-req-name-simpl").innerHTML = (ocspReqSimpl.tbsRequest.requestorName.type === 3) ? "<type \"x400Address\">" : "<type \"ediPartyName\">";
				document.getElementById("ocsp-req-nm-simpl").style.display = "block";
				break;
			case 4: // directoryName
				{
					let rdnmap = {
						"2.5.4.6": "C",
						"2.5.4.10": "OU",
						"2.5.4.11": "O",
						"2.5.4.3": "CN",
						"2.5.4.7": "L",
						"2.5.4.8": "S",
						"2.5.4.12": "T",
						"2.5.4.42": "GN",
						"2.5.4.43": "I",
						"2.5.4.4": "SN",
						"1.2.840.113549.1.9.1": "E-mail"
					};
					
					for(let i = 0; i < ocspReqSimpl.tbsRequest.requestorName.value.typesAndValues.length; i++)
					{
						let typeval = rdnmap[ocspReqSimpl.tbsRequest.requestorName.value.typesAndValues[i].type];
						if(typeof typeval === "undefined")
							typeval = ocspReqSimpl.tbsRequest.requestorName.value.typesAndValues[i].type;
						
						let subjval = ocspReqSimpl.tbsRequest.requestorName.value.typesAndValues[i].value.valueBlock.value;
						
						let row = requestorTable.insertRow(requestorTable.rows.length);
						let cell0 = row.insertCell(0);
						cell0.innerHTML = typeval;
						let cell1 = row.insertCell(1);
						cell1.innerHTML = subjval;
					}
					
					document.getElementById("ocsp-req-name-div").style.display = "block";
				}
				break;
		}
	}
	//endregion 
	
	//region Put information about requests 
	for(let i = 0; i < ocspReqSimpl.tbsRequest.requestList.length; i++)
	{
		let row = requestsTable.insertRow(requestsTable.rows.length);
		let cell0 = row.insertCell(0);
		cell0.innerHTML = bufferToHexCodes(ocspReqSimpl.tbsRequest.requestList[i].reqCert.serialNumber.valueBlock.valueHex);
	}
	//endregion 
	
	//region Put information about request extensions 
	if("requestExtensions" in ocspReqSimpl.tbsRequest)
	{
		for(let i = 0; i < ocspReqSimpl.tbsRequest.requestExtensions.length; i++)
		{
			let row = extensionTable.insertRow(extensionTable.rows.length);
			let cell0 = row.insertCell(0);
			cell0.innerHTML = ocspReqSimpl.tbsRequest.requestExtensions[i].extnID;
		}
		
		document.getElementById("ocsp-req-extn-div").style.display = "block";
	}
	//endregion 
}
//*********************************************************************************
//endregion 
//*********************************************************************************
