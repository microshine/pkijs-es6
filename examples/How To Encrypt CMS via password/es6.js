import * as asn1js from "asn1js";
import { arrayBufferToString, stringToArrayBuffer } from "pvutils";
import EnvelopedData from "pkijs/src/EnvelopedData";
import ContentInfo from "pkijs/src/ContentInfo";
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
		
		resultString = `${resultString}${pemString[i]}`;
	}
	
	return resultString;
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Encrypt input data
//*********************************************************************************
export function envelopedEncrypt()
{
	//region Get type of content encryption
	let encryptionVariant = 2;
	let encryptionSelect = document.getElementById("content_type").value;
	switch(encryptionSelect)
	{
		case "type_pass":
			encryptionVariant = 2;
			break;
		case "type_kek":
			encryptionVariant = 1;
			break;
		default:
	}
	//endregion
	
	//region Get input pre-defined data
	let preDefinedDataBuffer = stringToArrayBuffer(document.getElementById("password").value);
	
	/*
	 This is an example only and we consider that key encryption algorithm
	 has key length in 256 bits (default value).
	 */
	if(encryptionVariant === 1)
	{
		if(preDefinedDataBuffer.byteLength > 32)
		{
			let newPreDefinedDataBuffer = new ArrayBuffer(32);
			let newPreDefinedDataView = new Uint8Array(newPreDefinedDataBuffer);
			
			let preDefinedDataView = new Uint8Array(preDefinedDataBuffer);
			
			for(let i = 0; i < 32; i++)
				newPreDefinedDataView[i] = preDefinedDataView[i];
			
			preDefinedDataBuffer = newPreDefinedDataBuffer;
		}
		
		if(preDefinedDataBuffer.byteLength < 32)
		{
			let newPreDefinedDataBuffer = new ArrayBuffer(32);
			let newPreDefinedDataView = new Uint8Array(newPreDefinedDataBuffer);
			
			let preDefinedDataView = new Uint8Array(preDefinedDataBuffer);
			
			for(let i = 0; i < preDefinedDataBuffer.byteLength; i++)
				newPreDefinedDataView[i] = preDefinedDataView[i];
			
			preDefinedDataBuffer = newPreDefinedDataBuffer;
		}
		
	}
	//endregion
	
	//region Create WebCrypto form of content encryption algorithm
	let encryptionAlgorithm = {};
	
	let encryptionAlgorithmSelect = document.getElementById("content_enc_alg").value;
	switch(encryptionAlgorithmSelect)
	{
		case "alg_CBC":
			encryptionAlgorithm.name = "AES-CBC";
			break;
		case "alg_GCM":
			encryptionAlgorithm.name = "AES-GCM";
			break;
		default:
	}
	
	let encryptionAlgorithmLengthSelect = document.getElementById("content_enc_alg_len").value;
	switch(encryptionAlgorithmLengthSelect)
	{
		case "len_128":
			encryptionAlgorithm.length = 128;
			break;
		case "len_192":
			encryptionAlgorithm.length = 192;
			break;
		case "len_256":
			encryptionAlgorithm.length = 256;
			break;
		default:
	}
	//endregion
	
	let cmsEnveloped = new EnvelopedData();
	
	cmsEnveloped.addRecipientByPreDefinedData(preDefinedDataBuffer, {}, encryptionVariant);
	
	cmsEnveloped.encrypt(encryptionAlgorithm, stringToArrayBuffer(document.getElementById("content").value)).
	then(
		() => {
			let cmsContentSimpl = new ContentInfo();
			cmsContentSimpl.contentType = "1.2.840.113549.1.7.3";
			cmsContentSimpl.content = cmsEnveloped.toSchema();
			
			let schema = cmsContentSimpl.toSchema();
			let ber = schema.toBER(false);
			
			let berString = String.fromCharCode.apply(null, new Uint8Array(ber));
			
			let resultString = "-----BEGIN CMS-----\r\n";
			resultString = resultString + formatPEM(window.btoa(berString));
			resultString = resultString + "\r\n-----END CMS-----\r\n";
			
			document.getElementById("encrypted_content").innerHTML = resultString;
			
			alert("Encryption process finished successfully");
		},
		error => alert("ERROR DURING ENCRYPTION PROCESS: " + error)
	);
}
//*********************************************************************************
//endregion
//*********************************************************************************
//region Decrypt input data
//*********************************************************************************
export function envelopedDecrypt()
{
	//region Get type of content encryption
	let encryptionVariant = 2;
	let encryptionSelect = document.getElementById("content_type").value;
	switch(encryptionSelect)
	{
		case "type_pass":
			encryptionVariant = 2;
			break;
		case "type_kek":
			encryptionVariant = 1;
			break;
		default:
	}
	//endregion
	
	//region Get input pre-defined data
	let preDefinedDataBuffer = stringToArrayBuffer(document.getElementById("password").value);
	
	/*
	 This is an example only and we consider that key encryption algorithm
	 has key length in 256 bits (default value).
	 */
	if(encryptionVariant === 1)
	{
		if(preDefinedDataBuffer.byteLength > 32)
		{
			let newPreDefinedDataBuffer = new ArrayBuffer(32);
			let newPreDefinedDataView = new Uint8Array(newPreDefinedDataBuffer);
			
			let preDefinedDataView = new Uint8Array(preDefinedDataBuffer);
			
			for(let i = 0; i < 32; i++)
				newPreDefinedDataView[i] = preDefinedDataView[i];
			
			preDefinedDataBuffer = newPreDefinedDataBuffer;
		}
		
		if(preDefinedDataBuffer.byteLength < 32)
		{
			let newPreDefinedDataBuffer = new ArrayBuffer(32);
			let newPreDefinedDataView = new Uint8Array(newPreDefinedDataBuffer);
			
			let preDefinedDataView = new Uint8Array(preDefinedDataBuffer);
			
			for(let i = 0; i < preDefinedDataBuffer.byteLength; i++)
				newPreDefinedDataView[i] = preDefinedDataView[i];
			
			preDefinedDataBuffer = newPreDefinedDataBuffer;
		}
		
	}
	//endregion
	
	//region Decode CMS Enveloped content
	let encodedCMSEnveloped = document.getElementById("encrypted_content").innerHTML;
	let clearEncodedCMSEnveloped = encodedCMSEnveloped.replace(/(-----(BEGIN|END)( NEW)? CMS-----|\n)/g, '');
	let cmsEnvelopedBuffer = stringToArrayBuffer(window.atob(clearEncodedCMSEnveloped));
	
	let asn1 = asn1js.fromBER(cmsEnvelopedBuffer);
	let cmsContentSimpl = new ContentInfo({ schema: asn1.result });
	let cmsEnvelopedSimp = new EnvelopedData({ schema: cmsContentSimpl.content });
	//endregion
	
	cmsEnvelopedSimp.decrypt(0,
		{
			preDefinedData: preDefinedDataBuffer
		}).then(
		result => document.getElementById("decrypted_content").innerHTML = arrayBufferToString(result),
		error => alert("ERROR DURING DECRYPTION PROCESS: " + error)
	);
}
//*********************************************************************************
//endregion
//*********************************************************************************
