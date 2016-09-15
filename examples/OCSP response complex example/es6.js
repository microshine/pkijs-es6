import * as asn1js from "asn1js";
import { bufferToHexCodes, arrayBufferToString, stringToArrayBuffer } from "pvutils";
import { getCrypto, getAlgorithmParameters } from "pkijs/src/common";
import OCSPResponse from "pkijs/src/OCSPResponse";
import BasicOCSPResponse from "pkijs/src/BasicOCSPResponse";
import Certificate from "pkijs/src/Certificate";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import Extension from "pkijs/src/Extension";
import ResponseBytes from "pkijs/src/ResponseBytes";
import SingleResponse from "pkijs/src/SingleResponse";
import RelativeDistinguishedNames from "pkijs/src/RelativeDistinguishedNames";
import BasicConstraints from "pkijs/src/BasicConstraints";
//*********************************************************************************
let ocspResponseBuffer; // ArrayBuffer with loaded or created OCSP response
let trustedCertificates = []; // Array of root certificates from "CA Bundle"
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
		event => {
			ocspResponseBuffer = event.target.result;
			parseOCSPResp();
		};
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
export function handleCABundle(evt)
{
	let tempReader = new FileReader();
	
	let currentFiles = evt.target.files;
	
	tempReader.onload =
		event => parseCAbundle(event.target.result);
	
	tempReader.readAsArrayBuffer(currentFiles[0]);
}
//*********************************************************************************
//endregion 
//*********************************************************************************
//region Create OCSP response 
//*********************************************************************************
export function createOCSPResp()
{
	//region Initial variables 
	let sequence = Promise.resolve();
	
	let ocspRespSimpl = new OCSPResponse();
	let ocspBasicResp = new BasicOCSPResponse();
	
	let certSimpl = new Certificate();
	
	let publicKey;
	let privateKey;
	
	let hashAlgorithm;
	const hashOption = document.getElementById("hash_alg").value;
	switch(hashOption)
	{
		case "alg_SHA1":
			hashAlgorithm = "sha-1";
			break;
		case "alg_SHA256":
			hashAlgorithm = "sha-256";
			break;
		case "alg_SHA384":
			hashAlgorithm = "sha-384";
			break;
		case "alg_SHA512":
			hashAlgorithm = "sha-512";
			break;
		default:
	}
	
	let signatureAlgorithmName;
	const signOption = document.getElementById("sign_alg").value;
	switch(signOption)
	{
		case "alg_RSA15":
			signatureAlgorithmName = "RSASSA-PKCS1-V1_5";
			break;
		case "alg_RSA2":
			signatureAlgorithmName = "RSA-PSS";
			break;
		case "alg_ECDSA":
			signatureAlgorithmName = "ECDSA";
			break;
		default:;
	}
	//endregion 
	
	//region Get a "crypto" extension 
	const crypto = getCrypto();
	if(typeof crypto == "undefined")
	{
		alert("No WebCrypto extension found");
		return;
	}
	//endregion 
	
	//region Put a static values 
	certSimpl.version = 2;
	certSimpl.serialNumber = new asn1js.Integer({ value: 1 });
	certSimpl.issuer.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.6", // Country name
		value: new asn1js.PrintableString({ value: "RU" })
	}));
	certSimpl.issuer.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3", // Common name
		value: new asn1js.BmpString({ value: "Test" })
	}));
	certSimpl.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.6", // Country name
		value: new asn1js.PrintableString({ value: "RU" })
	}));
	certSimpl.subject.typesAndValues.push(new AttributeTypeAndValue({
		type: "2.5.4.3", // Common name
		value: new asn1js.BmpString({ value: "Test" })
	}));
	
	certSimpl.notBefore.value = new Date(2016, 1, 1);
	certSimpl.notAfter.value = new Date(2019, 1, 1);
	
	certSimpl.extensions = []; // Extensions are not a part of certificate by default, it's an optional array
	
	//region "BasicConstraints" extension
	let basicConstr = new BasicConstraints({
	   cA: true,
	   pathLenConstraint: 3
	});
	
	certSimpl.extensions.push(new Extension({
	   extnID: "2.5.29.19",
	   critical: false,
	   extnValue: basicConstr.toSchema().toBER(false),
	   parsedValue: basicConstr // Parsed value for well-known extensions
	}));
	//endregion 
	
	//region "KeyUsage" extension 
	const bitArray = new ArrayBuffer(1);
	const bitView = new Uint8Array(bitArray);
	
	bitView[0] = bitView[0] | 0x02; // Key usage "cRLSign" flag
	bitView[0] = bitView[0] | 0x04; // Key usage "keyCertSign" flag
	
	const keyUsage = new asn1js.BitString({ valueHex: bitArray });
	
	certSimpl.extensions.push(new Extension({
		extnID: "2.5.29.15",
		critical: false,
		extnValue: keyUsage.toBER(false),
		parsedValue: keyUsage // Parsed value for well-known extensions
	}));
	//endregion 
	//endregion 
	
	//region Create a new key pair 
	sequence = sequence.then(
		() => {
			//region Get default algorithm parameters for key generation 
			let algorithm = getAlgorithmParameters(signatureAlgorithmName, "generatekey");
			if("hash" in algorithm.algorithm)
				algorithm.algorithm.hash.name = hashAlgorithm;
			//endregion 
			
			return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
		}
	);
	//endregion 
	
	//region Store new key in an interim variables
	sequence = sequence.then(
		keyPair => {
			publicKey = keyPair.publicKey;
			privateKey = keyPair.privateKey;
		},
		error => alert("Error during key generation: " + error)
	);
	//endregion 
	
	//region Exporting public key into "subjectPublicKeyInfo" value of certificate 
	sequence = sequence.then(
		() => certSimpl.subjectPublicKeyInfo.importKey(publicKey)
	);
	//endregion 
	
	//region Signing final certificate 
	sequence = sequence.then(
		() => certSimpl.sign(privateKey, hashAlgorithm),
		error => alert(`Error during exporting public key: ${error}`)
	);
	//endregion 
	
	//region Encode and store certificate 
	sequence = sequence.then(
		() => {
			let certSimplEncoded = certSimpl.toSchema(true).toBER(false);
			
			let certSimplString = String.fromCharCode.apply(null, new Uint8Array(certSimplEncoded));
			
			let resultString = "-----BEGIN CERTIFICATE-----\r\n";
			resultString = resultString + formatPEM(window.btoa(certSimplString));
			resultString = resultString + "\r\n-----END CERTIFICATE-----\r\n";
			
			document.getElementById("new_signed_data").innerHTML = resultString;
			
			alert("Certificate created successfully!");
		},
		error => alert(`Error during signing: ${error}`)
	);
	//endregion 
	
	//region Exporting private key 
	sequence = sequence.then(
		() => crypto.exportKey("pkcs8", privateKey)
	);
	//endregion 
	
	//region Store exported key on Web page 
	sequence = sequence.then(
		result => {
			let privateKeyString = String.fromCharCode.apply(null, new Uint8Array(result));
			
			let resultString = document.getElementById("new_signed_data").innerHTML;
			
			resultString = resultString + "\r\n-----BEGIN PRIVATE KEY-----\r\n";
			resultString = resultString + formatPEM(window.btoa(privateKeyString));
			resultString = resultString + "\r\n-----END PRIVATE KEY-----\r\n";
			
			document.getElementById("new_signed_data").innerHTML = resultString;
			
			alert("Private key exported successfully!");
		},
		error => alert(`Error during exporting of private key: ${error}`)
	);
	//endregion 
	
	//region Create specific TST info structure to sign 
	sequence = sequence.then(
		() => {
			ocspRespSimpl.responseStatus.valueBlock.valueDec = 0; // success
			ocspRespSimpl.responseBytes = new ResponseBytes();
			ocspRespSimpl.responseBytes.responseType = "1.3.6.1.5.5.7.48.1.1";
			
			let responderIDBuffer = new ArrayBuffer(1);
			let responderIDView = new Uint8Array(responderIDBuffer);
			responderIDView[0] = 0x01;
			
			ocspBasicResp.tbsResponseData.responderID = certSimpl.issuer;
			ocspBasicResp.tbsResponseData.producedAt = new Date();
			
			let response = new SingleResponse();
			response.certID.hashAlgorithm.algorithmId = "1.3.14.3.2.26"; // SHA-1
			response.certID.issuerNameHash.valueBlock.valueHex = responderIDBuffer; // Fiction hash
			response.certID.issuerKeyHash.valueBlock.valueHex = responderIDBuffer; // Fiction hash
			response.certID.serialNumber.valueBlock.valueDec = 1; // Fiction serial number
			response.certStatus = new asn1js.Primitive({
				idBlock: {
					tagClass: 3, // CONTEXT-SPECIFIC
					tagNumber: 0 // [0]
				},
				lenBlockLength: 1 // The length contains one byte 0x00
			}); // status - success
			response.thisUpdate = new Date();
			
			ocspBasicResp.tbsResponseData.responses.push(response);
			
			ocspBasicResp.certs = [certSimpl];
			
			return ocspBasicResp.sign(privateKey, hashAlgorithm);
		}
	);
	//endregion 
	
	//region Finally create completed OCSP response structure
	sequence.then(
		function(result)
		{
			let encodedOCSPBasicResp = ocspBasicResp.toSchema().toBER(false);
			ocspRespSimpl.responseBytes.response = new asn1js.OctetString({ valueHex: encodedOCSPBasicResp });
			
			ocspResponseBuffer = ocspRespSimpl.toSchema().toBER(false);
			
			//region Convert ArrayBuffer to String 
			let signedDataString = "";
			
			const view = new Uint8Array(ocspResponseBuffer);
			
			for(let i = 0; i < view.length; i++)
				signedDataString = signedDataString + String.fromCharCode(view[i]);
			//endregion 
			
			trustedCertificates.push(certSimpl);
			
			let resultString = document.getElementById("new_signed_data").innerHTML;
			
			resultString = resultString + "\r\n-----BEGIN OCSP RESPONSE-----\r\n";
			resultString = resultString + formatPEM(window.btoa(signedDataString));
			resultString = resultString + "\r\n-----END OCSP RESPONSE-----\r\n\r\n";
			
			document.getElementById("new_signed_data").innerHTML = resultString;
			
			parseOCSPResp();
			
			alert("OCSP response has created successfully!");
		}
	);
	//endregion 
}
//*********************************************************************************
//endregion 
//*********************************************************************************
//region Parse existing OCSP response 
//*********************************************************************************
function parseOCSPResp()
{
	//region Initial variables 
	let ocspBasicResp;
	//endregion 
	
	//region Initial activities 
	document.getElementById("ocsp-resp-extensions").style.display = "none";
	document.getElementById("ocsp-resp-rspid-rdn").style.display = "none";
	document.getElementById("ocsp-resp-rspid-simpl").style.display = "none";
	
	const respIDTable = document.getElementById("ocsp-resp-respid-rdn");
	while(respIDTable.rows.length > 1)
		respIDTable.deleteRow(respIDTable.rows.length - 1);
	
	const extensionTable = document.getElementById("ocsp-resp-extensions-table");
	while(extensionTable.rows.length > 1)
		extensionTable.deleteRow(extensionTable.rows.length - 1);
	
	const responsesTable = document.getElementById("ocsp-resp-attr-table");
	while(extensionTable.rows.length > 1)
		extensionTable.deleteRow(extensionTable.rows.length - 1);
	//endregion
	
	//region Decode existing OCSP response 
	const asn1 = asn1js.fromBER(ocspResponseBuffer);
	const ocspRespSimpl = new OCSPResponse({ schema: asn1.result });
	//endregion 
	
	//region Put information about overall response status 
	let status = "";
	
	switch(ocspRespSimpl.responseStatus.valueBlock.valueDec)
	{
		case 0:
			status = "successful";
			break;
		case 1:
			status = "malformedRequest";
			break;
		case 2:
			status = "internalError";
			break;
		case 3:
			status = "tryLater";
			break;
		case 4:
			status = "<not used>";
			break;
		case 5:
			status = "sigRequired";
			break;
		case 6:
			status = "unauthorized";
			break;
		default:
			alert("Wrong OCSP response status");
			return;
	}
	
	document.getElementById("resp-status").innerHTML = status;
	//endregion 
	
	//region Check that we do have "responseBytes" 
	if("responseBytes" in ocspRespSimpl)
	{
		let asn1Basic = asn1js.fromBER(ocspRespSimpl.responseBytes.response.valueBlock.valueHex);
		ocspBasicResp = new BasicOCSPResponse({ schema: asn1Basic.result });
	}
	else
		return; // Nothing else to display - only status information exists
	//endregion 
	
	//region Put information about signature algorithm 
	const algomap = {
		"1.2.840.113549.2.1": "MD2",
		"1.2.840.113549.1.1.2": "MD2 with RSA",
		"1.2.840.113549.2.5": "MD5",
		"1.2.840.113549.1.1.4": "MD5 with RSA",
		"1.3.14.3.2.26": "SHA1",
		"1.2.840.10040.4.3": "SHA1 with DSA",
		"1.2.840.10045.4.1": "SHA1 with ECDSA",
		"1.2.840.113549.1.1.5": "SHA1 with RSA",
		"2.16.840.1.101.3.4.2.4": "SHA224",
		"1.2.840.113549.1.1.14": "SHA224 with RSA",
		"2.16.840.1.101.3.4.2.1": "SHA256",
		"1.2.840.113549.1.1.11": "SHA256 with RSA",
		"2.16.840.1.101.3.4.2.2": "SHA384",
		"1.2.840.113549.1.1.12": "SHA384 with RSA",
		"2.16.840.1.101.3.4.2.3": "SHA512",
		"1.2.840.113549.1.1.13": "SHA512 with RSA"
	};
	
	let signatureAlgorithm = algomap[ocspBasicResp.signatureAlgorithm.algorithmId];
	if(typeof signatureAlgorithm === "undefined")
		signatureAlgorithm = ocspBasicResp.signatureAlgorithm.algorithmId;
	else
		signatureAlgorithm = signatureAlgorithm + " (" + ocspBasicResp.signatureAlgorithm.algorithmId + ")";
	
	document.getElementById("sig-algo").innerHTML = signatureAlgorithm;
	//endregion 
	
	//region Put information about "Responder ID" 
	if(ocspBasicResp.tbsResponseData.responderID instanceof RelativeDistinguishedNames)
	{
		const typemap = {
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
		
		for(let i = 0; i < ocspBasicResp.tbsResponseData.responderID.typesAndValues.length; i++)
		{
			let typeval = typemap[ocspBasicResp.tbsResponseData.responderID.typesAndValues[i].type];
			if(typeof typeval === "undefined")
				typeval = ocspBasicResp.tbsResponseData.responderID.typesAndValues[i].type;
			
			let subjval = ocspBasicResp.tbsResponseData.responderID.typesAndValues[i].value.valueBlock.value;
			
			let row = respIDTable.insertRow(respIDTable.rows.length);
			let cell0 = row.insertCell(0);
			cell0.innerHTML = typeval;
			let cell1 = row.insertCell(1);
			cell1.innerHTML = subjval;
		}
		
		document.getElementById("ocsp-resp-rspid-rdn").style.display = "block";
	}
	else
	{
		if(ocspBasicResp.tbsResponseData.responderID instanceof asn1js.OctetString)
		{
			document.getElementById("ocsp-resp-respid-simpl").innerHTML = bufferToHexCodes(ocspBasicResp.tbsResponseData.responderID.valueBlock.valueHex, 0, ocspBasicResp.tbsResponseData.responderID.valueBlock.valueHex.byteLength);
			document.getElementById("ocsp-resp-rspid-simpl").style.display = "block";
		}
		else
		{
			alert("Wrong OCSP response responderID");
			return;
		}
	}
	//endregion 
	
	//region Put information about a time when the response was produced 
	document.getElementById("prod-at").innerHTML = ocspBasicResp.tbsResponseData.producedAt.toString();
	//endregion 
	
	//region Put information about extensions of the OCSP response 
	if("responseExtensions" in ocspBasicResp)
	{
		let extenmap = {
			"1.3.6.1.5.5.7.48.1.2": "Nonce",
			"1.3.6.1.5.5.7.48.1.3": "CRL References",
			"1.3.6.1.5.5.7.48.1.4": "Acceptable Response Types",
			"1.3.6.1.5.5.7.48.1.6": "Archive Cutoff",
			"1.3.6.1.5.5.7.48.1.7": "Service Locator",
			"1.3.6.1.5.5.7.48.1.8": "Preferred Signature Algorithms",
			"1.3.6.1.5.5.7.48.1.9": "Extended Revoked Definition",
			"2.5.29.21": "CRL Reason",
			"2.5.29.24": "Invalidity Date",
			"2.5.29.29": "Certificate Issuer",
			"1.3.6.1.4.1.311.21.4": "Next Update"
		};
		
		for(let i = 0; i < ocspBasicResp.responseExtensions.length; i++)
		{
			let typeval = extenmap[ocspBasicResp.responseExtensions[i].extnID];
			if(typeof typeval === "undefined")
				typeval = ocspBasicResp.responseExtensions[i].extnID;
			
			let row = extensionTable.insertRow(extensionTable.rows.length);
			let cell0 = row.insertCell(0);
			cell0.innerHTML = typeval;
		}
		
		document.getElementById("ocsp-resp-extensions").style.display = "block";
	}
	//endregion 
	
	//region Put information about OCSP responses
	for(let i = 0; i < ocspBasicResp.tbsResponseData.responses.length; i++)
	{
		let typeval = bufferToHexCodes(ocspBasicResp.tbsResponseData.responses[i].certID.serialNumber.valueBlock.valueHex);
		let subjval = "";
		
		switch(ocspBasicResp.tbsResponseData.responses[i].certStatus.idBlock.tag_number)
		{
			case 0:
				subjval = "good";
				break;
			case 1:
				subjval = "revoked";
				break;
			case 2:
			default:
				subjval = "unknown";
		}
		
		let row = responsesTable.insertRow(responsesTable.rows.length);
		let cell0 = row.insertCell(0);
		cell0.innerHTML = typeval;
		let cell1 = row.insertCell(1);
		cell1.innerHTML = subjval;
	}
	//endregion 
	
	document.getElementById("ocsp-resp-data-block").style.display = "block";
}
//*********************************************************************************
//endregion 
//*********************************************************************************
//region Verify existing OCSP response 
//*********************************************************************************
export function verifyOCSPResp()
{
	//region Initial variables 
	let ocspBasicResp;
	//endregion 
	
	//region Decode existing OCSP response 
	const asn1 = asn1js.fromBER(ocspResponseBuffer);
	let ocspRespSimpl = new OCSPResponse({ schema: asn1.result });
	
	if("responseBytes" in ocspRespSimpl)
	{
		let asn1Basic = asn1js.fromBER(ocspRespSimpl.responseBytes.response.valueBlock.valueHex);
		ocspBasicResp = new BasicOCSPResponse({ schema: asn1Basic.result });
	}
	else
	{
		alert("No \"ResponseBytes\" in the OCSP Response - nothing to verify");
		return;
	}
	//endregion 
	
	//region Verify OCSP response 
	ocspBasicResp.verify({ trustedCerts: trustedCertificates }).
	then(
		function(result)
		{
			alert("Verification result: " + result);
		},
		function(error)
		{
			alert("Error during verification: " + error);
		}
	);
	//endregion 
}
//*********************************************************************************
//endregion 
//*********************************************************************************
//region Parse "CA Bundle" file 
//*********************************************************************************
export function parseCAbundle(buffer)
{
	//region Initial variables 
	let base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	
	let startChars = "-----BEGIN CERTIFICATE-----";
	let endChars = "-----END CERTIFICATE-----";
	let endLineChars = "\r\n";
	
	let view = new Uint8Array(buffer);
	
	let waitForStart = false;
	let middleStage = true;
	let waitForEnd = false;
	let waitForEndLine = false;
	let started = false;
	
	let certBodyEncoded = "";
	//endregion 
	
	for(let i = 0; i < view.length; i++)
	{
		if(started === true)
		{
			if(base64Chars.indexOf(String.fromCharCode(view[i])) !== (-1))
				certBodyEncoded = certBodyEncoded + String.fromCharCode(view[i]);
			else
			{
				if(String.fromCharCode(view[i]) === '-')
				{
					//region Decoded trustedCertificates 
					let asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certBodyEncoded)));
					try
					{
						trustedCertificates.push(new org.pkijs.simpl.CERT({ schema: asn1.result }));
					}
					catch(ex)
					{
						alert("Wrong certificate format");
						return;
					}
					//endregion 
					
					//region Set all "flag variables" 
					certBodyEncoded = "";
					
					started = false;
					waitForEnd = true;
					//endregion 
				}
			}
		}
		else
		{
			if(waitForEndLine === true)
			{
				if(endLineChars.indexOf(String.fromCharCode(view[i])) === (-1))
				{
					waitForEndLine = false;
					
					if(waitForEnd === true)
					{
						waitForEnd = false;
						middleStage = true;
					}
					else
					{
						if(waitForStart === true)
						{
							waitForStart = false;
							started = true;
							
							certBodyEncoded = certBodyEncoded + String.fromCharCode(view[i]);
						}
						else
							middleStage = true;
					}
				}
			}
			else
			{
				if(middleStage === true)
				{
					if(String.fromCharCode(view[i]) === "-")
					{
						if((i === 0) ||
							((String.fromCharCode(view[i - 1]) === "\r") ||
							(String.fromCharCode(view[i - 1]) === "\n")))
						{
							middleStage = false;
							waitForStart = true;
						}
					}
				}
				else
				{
					if(waitForStart === true)
					{
						if(startChars.indexOf(String.fromCharCode(view[i])) === (-1))
							waitForEndLine = true;
					}
					else
					{
						if(waitForEnd === true)
						{
							if(endChars.indexOf(String.fromCharCode(view[i])) === (-1))
								waitForEndLine = true;
						}
					}
				}
			}
		}
	}
}
//*********************************************************************************
//endregion 
//*********************************************************************************
