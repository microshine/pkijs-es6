import * as asn1js from "asn1js";
import { stringToArrayBuffer, bufferToHexCodes } from "pvutils";
import { getCrypto, getAlgorithmParameters } from "pkijs/src/common";
import Certificate from "pkijs/src/Certificate";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import Extension from "pkijs/src/Extension";
import TSTInfo from "pkijs/src/TSTInfo";
import MessageImprint from "pkijs/src/MessageImprint";
import AlgorithmIdentifier from "pkijs/src/AlgorithmIdentifier";
import Accuracy from "pkijs/src/Accuracy";
import EncapsulatedContentInfo from "pkijs/src/EncapsulatedContentInfo";
import SignedData from "pkijs/src/SignedData";
import SignerInfo from "pkijs/src/SignerInfo";
import IssuerAndSerialNumber from "pkijs/src/IssuerAndSerialNumber";
import ContentInfo from "pkijs/src/ContentInfo";
import TimeStampResp from "pkijs/src/TimeStampResp";
import PKIStatusInfo from "pkijs/src/PKIStatusInfo";
import BasicConstraints from "pkijs/src/BasicConstraints";
//*********************************************************************************
let tspResponseBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created TSP response
let trustedCertificates = []; // Array of root certificates from "CA Bundle"
let testData = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]);
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
	let current_index = 0;
	
	temp_reader.onload =
		function(event)
		{
			tspResponseBuffer = event.target.result;
			parseTSPResp();
		};
	
	temp_reader.readAsArrayBuffer(current_files[0]);
}
//*********************************************************************************
export function handleCABundle(evt)
{
	let temp_reader = new FileReader();
	
	let current_files = evt.target.files;
	
	temp_reader.onload =
		function(event)
		{
			parseCAbundle(event.target.result);
		};
	
	temp_reader.readAsArrayBuffer(current_files[0]);
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Create TSP response
//*********************************************************************************
export function createTSPResp()
{
	//region Initial variables
	let sequence = Promise.resolve();
	
	let certSimpl = new Certificate();
	let cmsSignedSimpl;
	
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
		default:
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
	let basic_constr = new BasicConstraints({
	   cA: true,
	   pathLenConstraint: 3
	});
	
	certSimpl.extensions.push(new Extension({
	   extnID: "2.5.29.19",
	   critical: false,
	   extnValue: basic_constr.toSchema().toBER(false),
	   parsedValue: basic_constr // Parsed value for well-known extensions
	}));
	//endregion
	
	//region "KeyUsage" extension
	let bit_array = new ArrayBuffer(1);
	let bit_view = new Uint8Array(bit_array);
	
	bit_view[0] = bit_view[0] | 0x02; // Key usage "cRLSign" flag
	bit_view[0] = bit_view[0] | 0x04; // Key usage "keyCertSign" flag
	
	let key_usage = new asn1js.BitString({ valueHex: bit_array });
	
	certSimpl.extensions.push(new Extension({
		extnID: "2.5.29.15",
		critical: false,
		extnValue: key_usage.toBER(false),
		parsedValue: key_usage // Parsed value for well-known extensions
	}));
	//endregion
	//endregion
	
	//region Create a new key pair
	sequence = sequence.then(
		function()
		{
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
		function(keyPair)
		{
			publicKey = keyPair.publicKey;
			privateKey = keyPair.privateKey;
		},
		function(error)
		{
			alert("Error during key generation: " + error);
		}
	);
	//endregion
	
	//region Exporting public key into "subjectPublicKeyInfo" value of certificate
	sequence = sequence.then(
		function()
		{
			return certSimpl.subjectPublicKeyInfo.importKey(publicKey);
		}
	);
	//endregion
	
	//region Signing final certificate
	sequence = sequence.then(
		function()
		{
			return certSimpl.sign(privateKey, hashAlgorithm);
		},
		function(error)
		{
			alert("Error during exporting public key: " + error);
		}
	);
	//endregion
	
	//region Encode and store certificate
	sequence = sequence.then(
		function()
		{
			let certSimplEncoded = certSimpl.toSchema(true).toBER(false);
			
			let certSimplString = String.fromCharCode.apply(null, new Uint8Array(certSimplEncoded));
			
			let result_string = "-----BEGIN CERTIFICATE-----\r\n";
			result_string = result_string + formatPEM(window.btoa(certSimplString));
			result_string = result_string + "\r\n-----END CERTIFICATE-----\r\n";
			
			document.getElementById("new_signed_data").innerHTML = result_string;
			
			alert("Certificate created successfully!");
		},
		function(error)
		{
			alert("Error during signing: " + error);
		}
	);
	//endregion
	
	//region Exporting private key
	sequence = sequence.then(
		function()
		{
			return crypto.exportKey("pkcs8", privateKey);
		}
	);
	//endregion
	
	//region Store exported key on Web page
	sequence = sequence.then(
		function(result)
		{
			let privateKeyString = String.fromCharCode.apply(null, new Uint8Array(result));
			
			let resultString = document.getElementById("new_signed_data").innerHTML;
			
			resultString = resultString + "\r\n-----BEGIN PRIVATE KEY-----\r\n";
			resultString = resultString + formatPEM(window.btoa(privateKeyString));
			resultString = resultString + "\r\n-----END PRIVATE KEY-----\r\n";
			
			document.getElementById("new_signed_data").innerHTML = resultString;
			
			alert("Private key exported successfully!");
		},
		function(error)
		{
			alert("Error during exporting of private key: " + error);
		}
	);
	//endregion
	
	//region Hash "testData" value
	sequence = sequence.then(
		function()
		{
			return crypto.digest(hashAlgorithm, testData);
		}
	);
	//endregion
	
	//region Create specific TST info structure to sign
	sequence = sequence.then(
		function(result)
		{
			let hashedBuffer = new ArrayBuffer(4);
			let hashedView = new Uint8Array(hashedBuffer);
			hashedView[0] = 0x7F;
			hashedView[1] = 0x02;
			hashedView[2] = 0x03;
			hashedView[3] = 0x04;
			
			let tstInfoSimpl = new TSTInfo({
				version: 1,
				policy: "1.1.1",
				messageImprint: new MessageImprint({
					hashAlgorithm: new AlgorithmIdentifier({ algorithmId: "1.3.14.3.2.26" }),
					hashedMessage: new asn1js.OctetString({ valueHex: result })
				}),
				serialNumber: new asn1js.Integer({ valueHex: hashedBuffer }),
				genTime: new Date(),
				ordering: true,
				accuracy: new Accuracy({
					seconds: 1,
					millis: 1,
					micros: 10
				}),
				nonce: new asn1js.Integer({ valueHex: hashedBuffer })
			});
			
			return tstInfoSimpl.toSchema().toBER(false);
		}
	);
	//endregion
	
	//region Initialize CMS Signed Data structures and sign it
	sequence = sequence.then(
		function(result)
		{
			let encapContent = new EncapsulatedContentInfo();
			encapContent.eContentType = "1.2.840.113549.1.9.16.1.4"; // "tSTInfo" content type
			encapContent.eContent = new asn1js.OctetString({ valueHex: result });
			
			cmsSignedSimpl = new SignedData({
				version: 3,
				encapContentInfo: encapContent,
				signerInfos: [
					new SignerInfo({
						version: 1,
						sid: new IssuerAndSerialNumber({
							issuer: certSimpl.issuer,
							serialNumber: certSimpl.serialNumber
						})
					})
				],
				certificates: [certSimpl]
			});
			
			return cmsSignedSimpl.sign(privateKey, 0, hashAlgorithm);
		}
	);
	//endregion
	
	//region Create internal CMS Signed Data
	sequence = sequence.then(
		function(result)
		{
			let cmsSignedSchema = cmsSignedSimpl.toSchema(true);
			
			const cmsContentSimp = new ContentInfo({
				contentType: "1.2.840.113549.1.7.2",
				content: cmsSignedSchema
			});
			
			return cmsContentSimp.toSchema(true);
		},
		function(error)
		{
			alert("Erorr during signing of CMS Signed Data: " + error);
		}
	);
	//endregion
	
	//region Finally create completed TSP response structure
	sequence.then(
		function(result)
		{
			let tspRespSimpl = new TimeStampResp({
				status: new PKIStatusInfo({ status: 0 }),
				timeStampToken: new ContentInfo({ schema: result })
			});
			
			//region Convert ArrayBuffer to String
			let signedDataString = "";
			
			let tspSchema = tspRespSimpl.toSchema();
			tspResponseBuffer = tspSchema.toBER(false);
			
			const view = new Uint8Array(tspResponseBuffer);
			
			for(let i = 0; i < view.length; i++)
				signedDataString = signedDataString + String.fromCharCode(view[i]);
			//endregion
			
			let resultString = document.getElementById("new_signed_data").innerHTML;
			
			resultString = resultString + "\r\n-----BEGIN TSP RESPONSE-----\r\n";
			resultString = resultString + formatPEM(window.btoa(signedDataString));
			resultString = resultString + "\r\n-----END TSP RESPONSE-----\r\n\r\n";
			
			document.getElementById("new_signed_data").innerHTML = resultString;
			
			parseTSPResp();
			
			alert("TSP response has created successfully!");
		}
	);
	//endregion
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Parse existing TSP response
//*********************************************************************************
export function parseTSPResp()
{
	//region Initial activities
	document.getElementById("resp-accur").style.display = "none";
	document.getElementById("resp-ord").style.display = "none";
	document.getElementById("resp-non").style.display = "none";
	document.getElementById("resp-ts-rdn").style.display = "none";
	document.getElementById("resp-ts-simpl").style.display = "none";
	document.getElementById("resp-ext").style.display = "none";
	
	const imprTable = document.getElementById("resp-imprint");
	while(imprTable.rows.length > 1)
		imprTable.deleteRow(imprTable.rows.length - 1);
	
	const accurTable = document.getElementById("resp-accuracy");
	while(accurTable.rows.length > 1)
		accurTable.deleteRow(accurTable.rows.length - 1);
	
	const tsTable = document.getElementById("resp-tsa");
	while(tsTable.rows.length > 1)
		tsTable.deleteRow(tsTable.rows.length - 1);
	
	const extTable = document.getElementById("resp-extensions");
	while(extTable.rows.length > 1)
		extTable.deleteRow(extTable.rows.length - 1);
	//endregion
	
	//region Decode existing TSP response
	let asn1 = asn1js.fromBER(tspResponseBuffer);
	let tspRespSimpl = new TimeStampResp({ schema: asn1.result });
	//endregion
	
	//region Put information about TSP response status
	let status = "";
	
	switch(tspRespSimpl.status.status)
	{
		case 0:
			status = "granted";
			break;
		case 1:
			status = "grantedWithMods";
			break;
		case 2:
			status = "rejection";
			break;
		case 3:
			status = "waiting";
			break;
		case 4:
			status = "revocationWarning";
			break;
		case 5:
			status = "revocationNotification";
			break;
		default:
	}
	
	document.getElementById("resp-status").innerHTML = status
	//endregion
	
	//region Parse internal CMS Signed Data
	if(("timeStampToken" in tspRespSimpl) === false)
	{
		alert("No additional info but PKIStatusInfo");
		return;
	}
	
	let signedSimpl = new SignedData({ schema: tspRespSimpl.timeStampToken.content });
	
	let asn1TST = asn1js.fromBER(signedSimpl.encapContentInfo.eContent.valueBlock.valueHex);
	let tstInfoSimpl = new TSTInfo({ schema: asn1TST.result });
	//endregion
	
	//region Put information about policy
	document.getElementById("resp-policy").innerHTML = tstInfoSimpl.policy;
	//endregion
	
	//region Put information about TST info message imprint
	const dgstmap = {
		"1.3.14.3.2.26": "SHA-1",
		"2.16.840.1.101.3.4.2.1": "SHA-256",
		"2.16.840.1.101.3.4.2.2": "SHA-384",
		"2.16.840.1.101.3.4.2.3": "SHA-512"
	};
	
	let hashAlgorithm = dgstmap[tstInfoSimpl.messageImprint.hashAlgorithm.algorithmId];
	if(typeof hashAlgorithm === "undefined")
		hashAlgorithm = tstInfoSimpl.messageImprint.hashAlgorithm.algorithmId;
	
	let imprintTable = document.getElementById("resp-imprint");
	
	let row = imprintTable.insertRow(imprintTable.rows.length);
	let cell0 = row.insertCell(0);
	cell0.innerHTML = hashAlgorithm;
	let cell1 = row.insertCell(1);
	cell1.innerHTML = bufferToHexCodes(tstInfoSimpl.messageImprint.hashedMessage.valueBlock.valueHex);
	//endregion
	
	//region Put information about TST info serial number
	document.getElementById("resp-serial").innerHTML = bufferToHexCodes(tstInfoSimpl.serialNumber.valueBlock.valueHex);
	//endregion
	
	//region Put information about the time when TST info was generated
	document.getElementById("resp-time").innerHTML = tstInfoSimpl.genTime.toString();
	//endregion
	
	//region Put information about TST info accuracy
	if("accuracy" in tstInfoSimpl)
	{
		let accuracyTable = document.getElementById("resp-accuracy");
		
		let row = accuracyTable.insertRow(accuracyTable.rows.length);
		let cell0 = row.insertCell(0);
		cell0.innerHTML = ("seconds" in tstInfoSimpl.accuracy) ? tstInfoSimpl.accuracy.seconds : 0;
		let cell1 = row.insertCell(1);
		cell1.innerHTML = ("millis" in tstInfoSimpl.accuracy) ? tstInfoSimpl.accuracy.millis : 0;
		let cell2 = row.insertCell(2);
		cell2.innerHTML = ("micros" in tstInfoSimpl.accuracy) ? tstInfoSimpl.accuracy.micros : 0;
		
		document.getElementById("resp-accur").style.display = "block";
	}
	//endregion
	
	//region Put information about TST info ordering
	if("ordering" in tstInfoSimpl)
	{
		document.getElementById("resp-ordering").innerHTML = tstInfoSimpl.ordering.toString();
		document.getElementById("resp-ord").style.display = "block";
	}
	//endregion
	
	//region Put information about TST info nonce value
	if("nonce" in tstInfoSimpl)
	{
		document.getElementById("resp-nonce").innerHTML = bufferToHexCodes(tstInfoSimpl.nonce.valueBlock.valueHex);
		document.getElementById("resp-non").style.display = "block";
	}
	//endregion
	
	//region Put information about TST info TSA
	if("tsa" in tstInfoSimpl)
	{
		switch(tstInfoSimpl.tsa.type)
		{
			case 1: // rfc822Name
			case 2: // dNSName
			case 6: // uniformResourceIdentifier
				document.getElementById("resp-tsa-simpl").innerHTML = tstInfoSimpl.tsa.value.valueBlock.value;
				document.getElementById("resp-ts-simpl").style.display = "block";
				break;
			case 7: // iPAddress
				{
					const view = new Uint8Array(tstInfoSimpl.tsa.value.valueBlock.valueHex);
					
					document.getElementById("resp-tsa-simpl").innerHTML = view[0].toString() + "." + view[1].toString() + "." + view[2].toString() + "." + view[3].toString();
					document.getElementById("resp-ts-simpl").style.display = "block";
				}
				break;
			case 3: // x400Address
			case 5: // ediPartyName
				document.getElementById("resp-tsa-simpl").innerHTML = (tstInfoSimpl.tsa.type === 3) ? "<type \"x400Address\">" : "<type \"ediPartyName\">";
				document.getElementById("resp-ts-simpl").style.display = "block";
				break;
			case 4: // directoryName
				{
					const rdnmap = {
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
					
					let rdnTable = document.getElementById("resp-tsa");
					
					for(let i = 0; i < tstInfoSimpl.tsa.value.typesAndValues.length; i++)
					{
						let typeval = rdnmap[tstInfoSimpl.tsa.value.typesAndValues[i].type];
						if(typeof typeval === "undefined")
							typeval = tstInfoSimpl.tsa.value.typesAndValues[i].type;
						
						let subjval = tstInfoSimpl.tsa.value.typesAndValues[i].value.valueBlock.value;
						
						let row = rdnTable.insertRow(rdnTable.rows.length);
						let cell0 = row.insertCell(0);
						cell0.innerHTML = typeval;
						let cell1 = row.insertCell(1);
						cell1.innerHTML = subjval;
					}
					
					document.getElementById("resp-ts-rdn").style.display = "block";
				}
				break;
		}
	}
	//endregion
	
	//region Put information about TST info extensions
	if("extensions" in tstInfoSimpl)
	{
		let extensionTable = document.getElementById("resp-extensions");
		
		for(let i = 0; i < tstInfoSimpl.extensions.length; i++)
		{
			let row = extensionTable.insertRow(extensionTable.rows.length);
			let cell0 = row.insertCell(0);
			cell0.innerHTML = tstInfoSimpl.extensions[i].extnID;
		}
		
		document.getElementById("resp-ext").style.display = "block";
	}
	//endregion
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Verify existing TSP response
//*********************************************************************************
export function verifyTSPResp()
{
	//region Decode existing TSP response
	let asn1 = asn1js.fromBER(tspResponseBuffer);
	let tspRespSimpl = new TimeStampResp({ schema: asn1.result });
	//endregion
	
	//region Verify TSP response
	tspRespSimpl.verify({ signer: 0, trustedCerts: trustedCertificates, data: testData.buffer }).
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
function parseCAbundle(buffer)
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
					let asn1 = org.pkijs.fromBER(stringToArrayBuffer(window.atob(certBodyEncoded)));
					try
					{
						trustedCertificates.push(new Certificate({ schema: asn1.result }));
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
