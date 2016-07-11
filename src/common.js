import * as asn1js from "asn1js";
import AlgorithmIdentifier from "AlgorithmIdentifier";
import RSASSAPSSParams from "RSASSAPSSParams";
import CryptoEngine from "CryptoEngine";
//**************************************************************************************
//region Crypto engine related function
//**************************************************************************************
let engine = {
	name: "none",
	crypto: null,
	subtle: null
};
//**************************************************************************************
export function setEngine(name, crypto, subtle)
{
	engine = {
		name,
		crypto,
		subtle
	};
}
//**************************************************************************************
export function getEngine()
{
	return engine;
}
//**************************************************************************************
(function initCryptoEngine()
{
	if(typeof window !== "undefined")
	{
		if("crypto" in window)
		{
			const engineName = "webcrypto";
			const cryptoObject = window.crypto;
			let subtleObject = null;

			// Apple Safari support
			if("webkitSubtle" in window.crypto)
				subtleObject = window.crypto.webkitSubtle;

			if("subtle" in window.crypto)
				subtleObject = window.crypto.subtle;

			engine = {
				name: engineName,
				crypto: cryptoObject,
				subtle: new CryptoEngine({ crypto: subtleObject })
			};
		}
	}
}
)();
//**************************************************************************************
//endregion
//**************************************************************************************
//region Declaration of common functions
//**************************************************************************************
/**
 * Get crypto subtle from current "crypto engine" or "undefined"
 * @returns {({decrypt, deriveKey, digest, encrypt, exportKey, generateKey, importKey, sign, unwrapKey, verify, wrapKey}|null)}
 */
export function getCrypto()
{
	if(engine.subtle !== null)
		return engine.subtle;

	return undefined;
}
//**************************************************************************************
/**
 * Initialize input Uint8Array by random values (with help from current "crypto engine")
 * @param {!Uint8Array} view
 * @returns {*}
 */
export function getRandomValues(view)
{
	if(engine.crypto !== null)
		return engine.crypto.getRandomValues(view);

	throw new Error("No support for Web Cryptography API");
}
//**************************************************************************************
/**
 * Get OID for each specific WebCrypto algorithm
 * @param {Object} algorithm WebCrypto algorithm
 * @returns {string}
 */
export function getOIDByAlgorithm(algorithm)
{
	let result = "";

	switch(algorithm.name.toUpperCase())
	{
		case "RSASSA-PKCS1-V1_5":
			switch(algorithm.hash.name.toUpperCase())
			{
				case "SHA-1":
					result = "1.2.840.113549.1.1.5";
					break;
				case "SHA-256":
					result = "1.2.840.113549.1.1.11";
					break;
				case "SHA-384":
					result = "1.2.840.113549.1.1.12";
					break;
				case "SHA-512":
					result = "1.2.840.113549.1.1.13";
					break;
				default:
			}
			break;
		case "RSA-PSS":
			result = "1.2.840.113549.1.1.10";
			break;
		case "RSA-OAEP":
			result = "1.2.840.113549.1.1.7";
			break;
		case "ECDSA":
			switch(algorithm.hash.name.toUpperCase())
			{
				case "SHA-1":
					result = "1.2.840.10045.4.1";
					break;
				case "SHA-256":
					result = "1.2.840.10045.4.3.2";
					break;
				case "SHA-384":
					result = "1.2.840.10045.4.3.3";
					break;
				case "SHA-512":
					result = "1.2.840.10045.4.3.4";
					break;
				default:
			}
			break;
		case "ECDH":
			switch(algorithm.kdf.toUpperCase()) // Non-standard addition - hash algorithm of KDF function
			{
				case "SHA-1":
					result = "1.3.133.16.840.63.0.2"; // dhSinglePass-stdDH-sha1kdf-scheme
					break;
				case "SHA-256":
					result = "1.3.132.1.11.1"; // dhSinglePass-stdDH-sha256kdf-scheme
					break;
				case "SHA-384":
					result = "1.3.132.1.11.2"; // dhSinglePass-stdDH-sha384kdf-scheme
					break;
				case "SHA-512":
					result = "1.3.132.1.11.3"; // dhSinglePass-stdDH-sha512kdf-scheme
					break;
				default:
			}
			break;
		case "AES-CTR":
			break;
		case "AES-CBC":
			switch(algorithm.length)
			{
				case 128:
					result = "2.16.840.1.101.3.4.1.2";
					break;
				case 192:
					result = "2.16.840.1.101.3.4.1.22";
					break;
				case 256:
					result = "2.16.840.1.101.3.4.1.42";
					break;
				default:
			}
			break;
		case "AES-CMAC":
			break;
		case "AES-GCM":
			switch(algorithm.length)
			{
				case 128:
					result = "2.16.840.1.101.3.4.1.6";
					break;
				case 192:
					result = "2.16.840.1.101.3.4.1.26";
					break;
				case 256:
					result = "2.16.840.1.101.3.4.1.46";
					break;
				default:
			}
			break;
		case "AES-CFB":
			switch(algorithm.length)
			{
				case 128:
					result = "2.16.840.1.101.3.4.1.4";
					break;
				case 192:
					result = "2.16.840.1.101.3.4.1.24";
					break;
				case 256:
					result = "2.16.840.1.101.3.4.1.44";
					break;
				default:
			}
			break;
		case "AES-KW":
			switch(algorithm.length)
			{
				case 128:
					result = "2.16.840.1.101.3.4.1.5";
					break;
				case 192:
					result = "2.16.840.1.101.3.4.1.25";
					break;
				case 256:
					result = "2.16.840.1.101.3.4.1.45";
					break;
				default:
			}
			break;
		case "HMAC":
			switch(algorithm.hash.name.toUpperCase())
			{
				case "SHA-1":
					result = "1.2.840.113549.2.7";
					break;
				case "SHA-256":
					result = "1.2.840.113549.2.9";
					break;
				case "SHA-384":
					result = "1.2.840.113549.2.10";
					break;
				case "SHA-512":
					result = "1.2.840.113549.2.11";
					break;
				default:
			}
			break;
		case "DH":
			result = "1.2.840.113549.1.9.16.3.5";
			break;
		case "SHA-1":
			result = "1.3.14.3.2.26";
			break;
		case "SHA-256":
			result = "2.16.840.1.101.3.4.2.1";
			break;
		case "SHA-384":
			result = "2.16.840.1.101.3.4.2.2";
			break;
		case "SHA-512":
			result = "2.16.840.1.101.3.4.2.3";
			break;
		case "CONCAT":
			break;
		case "HKDF":
			break;
		case "PBKDF2":
			result = "1.2.840.113549.1.5.12";
			break;
		//region Special case - OIDs for ECC curves
		case "P-256":
			result = "1.2.840.10045.3.1.7";
			break;
		case "P-384":
			result = "1.3.132.0.34";
			break;
		case "P-521":
			result = "1.3.132.0.35";
			break;
		//endregion
		default:
	}

	return result;
}
//**************************************************************************************
/**
 * Get default algorithm parameters for each kind of operation
 * @param {string} algorithmName Algorithm name to get common parameters for
 * @param {string} operation Kind of operation: "sign", "encrypt", "generatekey", "importkey", "exportkey", "verify"
 * @returns {*}
 */
export function getAlgorithmParameters(algorithmName, operation)
{
	let result = {
		algorithm: {},
		usages: []
	};

	switch(algorithmName.toUpperCase())
	{
		case "RSASSA-PKCS1-V1_5":
			switch(operation.toLowerCase())
			{
				case "generatekey":
					result = {
						algorithm: {
							name: "RSASSA-PKCS1-v1_5",
							modulusLength: 2048,
							publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["sign", "verify"]
					};
					break;
				case "verify":
				case "sign":
				case "importkey":
					result = {
						algorithm: {
							name: "RSASSA-PKCS1-v1_5",
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["verify"] // For importKey("pkcs8") usage must be "sign" only
					};
					break;
				case "exportkey":
				default:
					return {
						algorithm: {
							name: "RSASSA-PKCS1-v1_5"
						},
						usages: []
					};
			}
			break;
		case "RSA-PSS":
			switch(operation.toLowerCase())
			{
				case "sign":
				case "verify":
					result = {
						algorithm: {
							name: "RSA-PSS",
							hash: {
								name: "SHA-1"
							},
							saltLength: 20
						},
						usages: ["sign", "verify"]
					};
					break;
				case "generatekey":
					result = {
						algorithm: {
							name: "RSA-PSS",
							modulusLength: 2048,
							publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
							hash: {
								name: "SHA-1"
							}
						},
						usages: ["sign", "verify"]
					};
					break;
				case "importkey":
					result = {
						algorithm: {
							name: "RSA-PSS",
							hash: {
								name: "SHA-1"
							}
						},
						usages: ["verify"] // For importKey("pkcs8") usage must be "sign" only
					};
					break;
				case "exportkey":
				default:
					return {
						algorithm: {
							name: "RSA-PSS"
						},
						usages: []
					};
			}
			break;
		case "RSA-OAEP":
			switch(operation.toLowerCase())
			{
				case "encrypt":
				case "decrypt":
					result = {
						algorithm: {
							name: "RSA-OAEP"
						},
						usages: ["encrypt", "decrypt"]
					};
					break;
				case "generatekey":
					result = {
						algorithm: {
							name: "RSA-OAEP",
							modulusLength: 2048,
							publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				case "importkey":
					result = {
						algorithm: {
							name: "RSA-OAEP",
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["encrypt"] // encrypt for "spki" and decrypt for "pkcs8"
					};
					break;
				case "exportkey":
				default:
					return {
						algorithm: {
							name: "RSA-OAEP"
						},
						usages: []
					};
			}
			break;
		case "ECDSA":
			switch(operation.toLowerCase())
			{
				case "generatekey":
					result = {
						algorithm: {
							name: "ECDSA",
							namedCurve: "P-256"
						},
						usages: ["sign", "verify"]
					};
					break;
				case "importkey":
					result = {
						algorithm: {
							name: "ECDSA",
							namedCurve: "P-256"
						},
						usages: ["verify"] // "sign" for "pkcs8"
					};
					break;
				case "verify":
				case "sign":
					result = {
						algorithm: {
							name: "ECDSA",
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["sign"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "ECDSA"
						},
						usages: []
					};
			}
			break;
		case "ECDH":
			switch(operation.toLowerCase())
			{
				case "exportkey":
				case "importkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "ECDH",
							namedCurve: "P-256"
						},
						usages: ["deriveKey", "deriveBits"]
					};
					break;
				case "derivekey":
				case "derivebits":
					result = {
						algorithm: {
							name: "ECDH",
							namedCurve: "P-256",
							public: [] // Must be a "publicKey"
						},
						usages: ["encrypt", "decrypt"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "ECDH"
						},
						usages: []
					};
			}
			break;
		case "AES-CTR":
			switch(operation.toLowerCase())
			{
				case "importkey":
				case "exportkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "AES-CTR",
							length: 256
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				case "decrypt":
				case "encrypt":
					result = {
						algorithm: {
							name: "AES-CTR",
							counter: new Uint8Array(16),
							length: 10
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "AES-CTR"
						},
						usages: []
					};
			}
			break;
		case "AES-CBC":
			switch(operation.toLowerCase())
			{
				case "importkey":
				case "exportkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "AES-CBC",
							length: 256
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				case "decrypt":
				case "encrypt":
					result = {
						algorithm: {
							name: "AES-CBC",
							iv: getRandomValues(new Uint8Array(16)) // For "decrypt" the value should be replaced with value got on "encrypt" step
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "AES-CBC"
						},
						usages: []
					};
			}
			break;
		case "AES-GCM":
			switch(operation.toLowerCase())
			{
				case "importkey":
				case "exportkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "AES-GCM",
							length: 256
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				case "decrypt":
				case "encrypt":
					result = {
						algorithm: {
							name: "AES-GCM",
							iv: getRandomValues(new Uint8Array(16)) // For "decrypt" the value should be replaced with value got on "encrypt" step
						},
						usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "AES-GCM"
						},
						usages: []
					};
			}
			break;
		case "AES-KW":
			switch(operation.toLowerCase())
			{
				case "importkey":
				case "exportkey":
				case "generatekey":
				case "wrapkey":
				case "unwrapkey":
					result = {
						algorithm: {
							name: "AES-KW",
							length: 256
						},
						usages: ["wrapKey", "unwrapKey"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "AES-KW"
						},
						usages: []
					};
			}
			break;
		case "HMAC":
			switch(operation.toLowerCase())
			{
				case "sign":
				case "verify":
					result = {
						algorithm: {
							name: "HMAC"
						},
						usages: ["sign", "verify"]
					};
					break;
				case "importkey":
				case "exportkey":
				case "generatekey":
					result = {
						algorithm: {
							name: "HMAC",
							length: 32,
							hash: {
								name: "SHA-256"
							}
						},
						usages: ["sign", "verify"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "HMAC"
						},
						usages: []
					};
			}
			break;
		case "HKDF":
			switch(operation.toLowerCase())
			{
				case "derivekey":
					result = {
						algorithm: {
							name: "HKDF",
							hash: "SHA-256",
							salt: new Uint8Array([]),
							info: new Uint8Array([])
						},
						usages: ["encrypt", "decrypt"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "HKDF"
						},
						usages: []
					};
			}
			break;
		case "PBKDF2":
			switch(operation.toLowerCase())
			{
				case "derivekey":
					result = {
						algorithm: {
							name: "PBKDF2",
							hash: { name: "SHA-256" },
							salt: new Uint8Array([]),
							iterations: 1000
						},
						usages: ["encrypt", "decrypt"]
					};
					break;
				default:
					return {
						algorithm: {
							name: "PBKDF2"
						},
						usages: []
					};
			}
			break;
		default:
	}

	return result;
}
//**************************************************************************************
/**
 * Create CMS ECDSA signature from WebCrypto ECDSA signature
 * @param {ArrayBuffer} signatureBuffer WebCrypto result of "sign" function
 * @returns {ArrayBuffer}
 */
export function createCMSECDSASignature(signatureBuffer)
{
	// #region Initial check for correct length 
	if((signatureBuffer.byteLength % 2) !== 0)
		return new ArrayBuffer(0);
	// #endregion 
	
	// #region Initial variables 
	const length = signatureBuffer.byteLength / 2; // There are two equal parts inside incoming ArrayBuffer
	
	const rBuffer = new ArrayBuffer(length);
	const rView = new Uint8Array(rBuffer);
	rView.set(new Uint8Array(signatureBuffer, 0, length));
	let rCorrectedBuffer;
	let rCorrectedView;
	
	const sBuffer = new ArrayBuffer(length);
	const sView = new Uint8Array(sBuffer);
	sView.set(new Uint8Array(signatureBuffer, length, length));
	let sCorrectedBuffer;
	let sCorrectedView;
	// #endregion   
	
	// #region Get "r" part of ECDSA signature 
	switch(true)
	{
		case ((rView[0] & 0x80) !== 0):
			rCorrectedBuffer = new ArrayBuffer(length + 1);
			rCorrectedView = new Uint8Array(rCorrectedBuffer);
			
			rCorrectedView[0] = 0x00;
			
			rCorrectedView.set(rView, 1);
			break;
		case ((rView[0] === 0x00) && ((rView[1] & 0x80) === 0)):
			rCorrectedBuffer = new ArrayBuffer(length - 1);
			rCorrectedView = new Uint8Array(rCorrectedBuffer);
			
			rCorrectedView.set(new Uint8Array(signatureBuffer, 1, length - 1));
			break;
		default:
			rCorrectedBuffer = rBuffer;
			rCorrectedView = rView;
	}
	// #endregion   
	
	// #region Get "s" part of ECDSA signature 
	switch(true)
	{
		case ((sView[0] & 0x80) !== 0):
			sCorrectedBuffer = new ArrayBuffer(length + 1);
			sCorrectedView = new Uint8Array(sCorrectedBuffer);
			
			sCorrectedView[0] = 0x00;
			
			sCorrectedView.set(sView, 1);
			break;
		case ((sView[0] === 0x00) && ((sView[1] & 0x80) === 0)):
			sCorrectedBuffer = new ArrayBuffer(length - 1);
			sCorrectedView = new Uint8Array(sCorrectedBuffer);
			
			sCorrectedView.set(new Uint8Array(signatureBuffer, 1, length - 1));
			break;
		default:
			sCorrectedBuffer = sBuffer;
			sCorrectedView = sView;
	}
	// #endregion   
	
	// #region Create ASN.1 structure of CMS ECDSA signature 
	const rInteger = new asn1js.Integer();
	rInteger.valueBlock.isHexOnly = true;
	rInteger.valueBlock.valueHex = rCorrectedBuffer.slice();
	
	const sInteger = new asn1js.Integer();
	sInteger.valueBlock.isHexOnly = true;
	sInteger.valueBlock.valueHex = sCorrectedBuffer.slice();
	// #endregion
	
	return (new asn1js.Sequence({
		value: [
			rInteger,
			sInteger
		]
	})).toBER(false);
}
//**************************************************************************************
/**
 * String preparation function. In a future here will be realization of algorithm from RFC4518
 * @param {string} inputString JavaScript string. As soon as for each ASN.1 string type we have a specific transformation function here we will work with pure JavaScript string
 * @returns {string} Formated string
 */
export function stringPrep(inputString)
{
	let result = inputString.replace(/^\s+|\s+$/g, ""); // Trim input string
	result = result.replace(/\s+/g, " "); // Change all sequence of SPACE down to SPACE char
	result = result.toLowerCase();

	return result;
}
//**************************************************************************************
/**
 * Concatenate two ArrayBuffers
 * @param {!ArrayBuffer} inputBuf1 First ArrayBuffer (first part of concatenated array)
 * @param {!ArrayBuffer} inputBuf2 Second ArrayBuffer (second part of concatenated array)
 */
export function concatBuffers(inputBuf1, inputBuf2)
{
	const retBuf = new ArrayBuffer(inputBuf1.byteLength + inputBuf2.byteLength);
	const retView = new Uint8Array(retBuf);

	retView.set(new Uint8Array(inputBuf1));
	retView.set(new Uint8Array(inputBuf2), inputBuf1.byteLength);

	return retBuf;
}
//**************************************************************************************
/**
 * Create a single ArrayBuffer from CMS ECDSA signature
 * @param {Sequence} cmsSignature ASN.1 SEQUENCE contains CMS ECDSA signature
 * @returns {ArrayBuffer}
 */
export function createECDSASignatureFromCMS(cmsSignature)
{
	// #region Check input variables
	if((cmsSignature instanceof asn1js.Sequence) === false)
		return new ArrayBuffer(0);
	
	if(cmsSignature.valueBlock.value.length !== 2)
		return new ArrayBuffer(0);
	
	if((cmsSignature.valueBlock.value[0] instanceof asn1js.Integer) === false)
		return new ArrayBuffer(0);
	
	if((cmsSignature.valueBlock.value[1] instanceof asn1js.Integer) === false)
		return new ArrayBuffer(0);
	// #endregion 
	
	// #region Aux functions 
	function transformInteger(integer)
	{
		const view = new Uint8Array(integer.valueBlock.valueHex);
		
		switch(integer.valueBlock.valueHex.byteLength)
		{
			case 32:
			case 48:
			case 66:
				return integer.valueBlock.valueHex;
			case 33:
			case 49:
			case 67:
				return (view.slice(1)).buffer;
			case 31:
			case 47:
			case 65:
				{
					const updatedBuffer = new ArrayBuffer(integer.valueBlock.valueHex.byteLength + 1);
					const updatedView = new Uint8Array(updatedBuffer);

					updatedView.set(view, 1);

					return updatedBuffer;
				}
			default:
				return new ArrayBuffer(0);
		}
	}
	// #endregion 
	
	const rBuffer = transformInteger(cmsSignature.valueBlock.value[0]);
	const sBuffer = transformInteger(cmsSignature.valueBlock.value[1]);
	
	return concatBuffers(rBuffer, sBuffer);
}
//**************************************************************************************
/**
 * Get WebCrypto algorithm by wel-known OID
 * @param {string} oid Wel-known OID to search for
 * @returns {Object}
 */
export function getAlgorithmByOID(oid)
{
	switch(oid)
	{
		case "1.2.840.113549.1.1.5":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: {
					name: "SHA-1"
				}
			};
		case "1.2.840.113549.1.1.11":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: {
					name: "SHA-256"
				}
			};
		case "1.2.840.113549.1.1.12":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: {
					name: "SHA-384"
				}
			};
		case "1.2.840.113549.1.1.13":
			return {
				name: "RSASSA-PKCS1-v1_5",
				hash: {
					name: "SHA-512"
				}
			};
		case "1.2.840.113549.1.1.10":
			return {
				name: "RSA-PSS"
			};
		case "1.2.840.113549.1.1.7":
			return {
				name: "RSA-OAEP"
			};
		case "1.2.840.10045.4.1":
			return {
				name: "ECDSA",
				hash: {
					name: "SHA-1"
				}
			};
		case "1.2.840.10045.4.3.2":
			return {
				name: "ECDSA",
				hash: {
					name: "SHA-256"
				}
			};
		case "1.2.840.10045.4.3.3":
			return {
				name: "ECDSA",
				hash: {
					name: "SHA-384"
				}
			};
		case "1.2.840.10045.4.3.4":
			return {
				name: "ECDSA",
				hash: {
					name: "SHA-512"
				}
			};
		case "1.3.133.16.840.63.0.2":
			return {
				name: "ECDH",
				kdf: "SHA-1"
			};
		case "1.3.132.1.11.1":
			return {
				name: "ECDH",
				kdf: "SHA-256"
			};
		case "1.3.132.1.11.2":
			return {
				name: "ECDH",
				kdf: "SHA-384"
			};
		case "1.3.132.1.11.3":
			return {
				name: "ECDH",
				kdf: "SHA-512"
			};
		case "2.16.840.1.101.3.4.1.2":
			return {
				name: "AES-CBC",
				length: 128
			};
		case "2.16.840.1.101.3.4.1.22":
			return {
				name: "AES-CBC",
				length: 192
			};
		case "2.16.840.1.101.3.4.1.42":
			return {
				name: "AES-CBC",
				length: 256
			};
		case "2.16.840.1.101.3.4.1.6":
			return {
				name: "AES-GCM",
				length: 128
			};
		case "2.16.840.1.101.3.4.1.26":
			return {
				name: "AES-GCM",
				length: 192
			};
		case "2.16.840.1.101.3.4.1.46":
			return {
				name: "AES-GCM",
				length: 256
			};
		case "2.16.840.1.101.3.4.1.4":
			return {
				name: "AES-CFB",
				length: 128
			};
		case "2.16.840.1.101.3.4.1.24":
			return {
				name: "AES-CFB",
				length: 192
			};
		case "2.16.840.1.101.3.4.1.44":
			return {
				name: "AES-CFB",
				length: 256
			};
		case "2.16.840.1.101.3.4.1.5":
			return {
				name: "AES-KW",
				length: 128
			};
		case "2.16.840.1.101.3.4.1.25":
			return {
				name: "AES-KW",
				length: 192
			};
		case "2.16.840.1.101.3.4.1.45":
			return {
				name: "AES-KW",
				length: 256
			};
		case "1.2.840.113549.2.7":
			return {
				name: "HMAC",
				hash: {
					name: "SHA-1"
				}
			};
		case "1.2.840.113549.2.9":
			return {
				name: "HMAC",
				hash: {
					name: "SHA-256"
				}
			};
		case "1.2.840.113549.2.10":
			return {
				name: "HMAC",
				hash: {
					name: "SHA-384"
				}
			};
		case "1.2.840.113549.2.11":
			return {
				name: "HMAC",
				hash: {
					name: "SHA-512"
				}
			};
		case "1.2.840.113549.1.9.16.3.5":
			return {
				name: "DH"
			};
		case "1.3.14.3.2.26":
			return {
				name: "SHA-1"
			};
		case "2.16.840.1.101.3.4.2.1":
			return {
				name: "SHA-256"
			};
		case "2.16.840.1.101.3.4.2.2":
			return {
				name: "SHA-384"
			};
		case "2.16.840.1.101.3.4.2.3":
			return {
				name: "SHA-512"
			};
		case "1.2.840.113549.1.5.12":
			return {
				name: "PBKDF2"
			};
		//region Special case - OIDs for ECC curves
		case "1.2.840.10045.3.1.7":
			return {
				name: "P-256"
			};
		case "1.3.132.0.34":
			return {
				name: "P-384"
			};
		case "1.3.132.0.35":
			return {
				name: "P-521"
			};
		//endregion
		default:
	}

	return {};
}
//**************************************************************************************
/**
 * Getting hash algorithm by signature algorithm
 * @param {AlgorithmIdentifier} signatureAlgorithm Signature algorithm
 * @returns {string}
 */
export function getHashAlgorithm(signatureAlgorithm)
{
	let result = "";

	switch(signatureAlgorithm.algorithmId)
	{
		case "1.2.840.10045.4.1": // ecdsa-with-SHA1
		case "1.2.840.113549.1.1.5":
			result = "SHA-1";
			break;
		case "1.2.840.10045.4.3.2": // ecdsa-with-SHA256
		case "1.2.840.113549.1.1.11":
			result = "SHA-256";
			break;
		case "1.2.840.10045.4.3.3": // ecdsa-with-SHA384
		case "1.2.840.113549.1.1.12":
			result = "SHA-384";
			break;
		case "1.2.840.10045.4.3.4": // ecdsa-with-SHA512
		case "1.2.840.113549.1.1.13":
			result = "SHA-512";
			break;
		case "1.2.840.113549.1.1.10": // RSA-PSS
			{
				try
				{
					const params = new RSASSAPSSParams({ schema: signatureAlgorithm.algorithmParams });
					if("hashAlgorithm" in params)
					{
						const algorithm = getAlgorithmByOID(params.hashAlgorithm.algorithmId);
						if(("name" in algorithm) === false)
							return "";

						result = algorithm.name;
					}
					else
						result = "SHA-1";
				}
				catch(ex) {}
			}
			break;
		default:
	}

	return result;
}
//**************************************************************************************
/**
 * ANS X9.63 Key Derivation Function having a "Counter" as a parameter
 * @param {string} hashFunction Used hash function
 * @param {ArrayBuffer} Zbuffer ArrayBuffer containing ECDH shared secret to derive from
 * @param {number} Counter
 * @param {ArrayBuffer} SharedInfo Usually DER encoded "ECC_CMS_SharedInfo" structure
 */
export function kdfWithCounter(hashFunction, Zbuffer, Counter, SharedInfo)
{
	//region Check of input parameters
	switch(hashFunction.toUpperCase())
	{
		case "SHA-1":
		case "SHA-256":
		case "SHA-384":
		case "SHA-512":
			break;
		default:
			return Promise.reject(`Unknown hash function: ${hashFunction}`);
	}

	if((Zbuffer instanceof ArrayBuffer) === false)
		return Promise.reject("Please set \"Zbuffer\" as \"ArrayBuffer\"");

	if(Zbuffer.byteLength === 0)
		return Promise.reject("\"Zbuffer\" has zero length, error");

	if((SharedInfo instanceof ArrayBuffer) === false)
		return Promise.reject("Please set \"SharedInfo\" as \"ArrayBuffer\"");

	if(Counter > 255)
		return Promise.reject("Please set \"Counter\" variable to value less or equal to 255");
	//endregion

	//region Initial variables
	const counterBuffer = new ArrayBuffer(4);
	const counterView = new Uint8Array(counterBuffer);
	counterView[0] = 0x00;
	counterView[1] = 0x00;
	counterView[2] = 0x00;
	counterView[3] = Counter;

	let combinedBuffer = new ArrayBuffer(0);
	//endregion

	//region Get a "crypto" extension
	const crypto = getCrypto();
	if(typeof crypto === "undefined")
		return Promise.reject("Unable to create WebCrypto object");
	//endregion

	//region Create a combined ArrayBuffer for digesting
	combinedBuffer = concatBuffers(combinedBuffer, Zbuffer);
	combinedBuffer = concatBuffers(combinedBuffer, counterBuffer);
	combinedBuffer = concatBuffers(combinedBuffer, SharedInfo);
	//endregion

	//region Return digest of combined ArrayBuffer and information about current counter
	return crypto.digest({
		name: hashFunction
	},
	combinedBuffer).then(result => {
		return {
			counter: Counter,
			result
		};
	});
	//endregion
}
//**************************************************************************************
/**
 * ANS X9.63 Key Derivation Function
 * @param {string} hashFunction Used hash function
 * @param {ArrayBuffer} Zbuffer ArrayBuffer containing ECDH shared secret to derive from
 * @param {number} keydatalen Length (!!! in BITS !!!) of used kew derivation function
 * @param {ArrayBuffer} SharedInfo Usually DER encoded "ECC_CMS_SharedInfo" structure
 */
export function kdf(hashFunction, Zbuffer, keydatalen, SharedInfo)
{
	//region Initial variables
	let hashLength = 0;
	let maxCounter = 1;
	
	const kdfArray = [];
	//endregion
	
	//region Check of input parameters
	switch(hashFunction.toUpperCase())
	{
		case "SHA-1":
			hashLength = 160; // In bits
			break;
		case "SHA-256":
			hashLength = 256; // In bits
			break;
		case "SHA-384":
			hashLength = 384; // In bits
			break;
		case "SHA-512":
			hashLength = 512; // In bits
			break;
		default:
			return Promise.reject(`Unknown hash function: ${hashFunction}`);
	}
	
	if((Zbuffer instanceof ArrayBuffer) === false)
		return Promise.reject("Please set \"Zbuffer\" as \"ArrayBuffer\"");
	
	if(Zbuffer.byteLength === 0)
		return Promise.reject("\"Zbuffer\" has zero length, error");
	
	if((SharedInfo instanceof ArrayBuffer) === false)
		return Promise.reject("Please set \"SharedInfo\" as \"ArrayBuffer\"");
	//endregion
	
	//region Calculated maximum value of "Counter" variable
	const quotient = keydatalen / hashLength;
	
	if(Math.floor(quotient) > 0)
	{
		maxCounter = Math.floor(quotient);
		
		if((quotient - maxCounter) > 0)
			maxCounter++;
	}
	//endregion
	
	//region Create an array of "kdfWithCounter"
	for(let i = 1; i <= maxCounter; i++)
		kdfArray.push(kdfWithCounter(hashFunction, Zbuffer, i, SharedInfo));
	//endregion
	
	//region Return combined digest with specified length
	return Promise.all(kdfArray).
	then(incomingResult => {
		//region Initial variables
		let combinedBuffer = new ArrayBuffer(0);
		let currentCounter = 1;
		let found = true;
		//endregion

		//region Combine all buffer together
		while(found)
		{
			found = false;

			for(const result of incomingResult)
			{
				if(result.counter === currentCounter)
				{
					combinedBuffer = concatBuffers(combinedBuffer, result.result);
					found = true;
					break;
				}
			}

			currentCounter++;
		}
		//endregion

		//region Create output buffer with specified length
		keydatalen >>= 3; // Divide by 8 since "keydatalen" is in bits

		if(combinedBuffer.byteLength > keydatalen)
		{
			const newBuffer = new ArrayBuffer(keydatalen);
			const newView = new Uint8Array(newBuffer);
			const combinedView = new Uint8Array(combinedBuffer);

			for(let i = 0; i < keydatalen; i++)
				newView[i] = combinedView[i];

			return newBuffer;
		}

		return combinedBuffer; // Since the situation when "combinedBuffer.byteLength < keydatalen" here we have only "combinedBuffer.byteLength === keydatalen"
		//endregion
	});
	//endregion
}
//**************************************************************************************
//**************************************************************************************
/**
 * Get value for input parameters, or set a default value
 * @param {Object} parameters
 * @param {string} name
 * @param defaultValue
 */
export function getParametersValue(parameters, name, defaultValue)
{
	if(name in parameters)
		return parameters[name];

	return defaultValue;
}
//**************************************************************************************
/**
 * Converts "ArrayBuffer" into a hexdecimal string
 * @param {ArrayBuffer} inputBuffer
 * @param {number} inputOffset
 * @param {number} inputLength
 * @returns {string}
 */
export function bufferToHexCodes(inputBuffer, inputOffset, inputLength)
{
	let result = "";

	for(const item of (new Uint8Array(inputBuffer, inputOffset, inputLength)))
	{
		const str = item.toString(16).toUpperCase();
		result = result + ((str.length === 1) ? "0" : "") + str;
	}

	return result;
}
//**************************************************************************************
/**
 * Check input "ArrayBuffer" for common functions
 * @param {LocalBaseBlock} baseBlock
 * @param {ArrayBuffer} inputBuffer
 * @param {number} inputOffset
 * @param {number} inputLength
 * @returns {boolean}
 */
export function checkBufferParams(baseBlock, inputBuffer, inputOffset, inputLength)
{
	if((inputBuffer instanceof ArrayBuffer) === false)
	{
		baseBlock.error = "Wrong parameter: inputBuffer must be \"ArrayBuffer\"";
		return false;
	}

	if(inputBuffer.byteLength === 0)
	{
		baseBlock.error = "Wrong parameter: inputBuffer has zero length";
		return false;
	}

	if(inputOffset < 0)
	{
		baseBlock.error = "Wrong parameter: inputOffset less than zero";
		return false;
	}

	if(inputLength < 0)
	{
		baseBlock.error = "Wrong parameter: inputLength less than zero";
		return false;
	}

	if((inputBuffer.byteLength - inputOffset - inputLength) < 0)
	{
		baseBlock.error = "End of input reached before message was fully decoded (inconsistent offset and length values)";
		return false;
	}

	return true;
}
//**************************************************************************************
/**
 * Convert number from 2^base to 2^10
 * @param {Uint8Array} inputBuffer
 * @param {number} inputBase
 * @returns {number}
 */
export function utilFromBase(inputBuffer, inputBase)
{
	let result = 0;

	for(let i = (inputBuffer.length - 1); i >= 0; i--)
		result += inputBuffer[(inputBuffer.length - 1) - i] * Math.pow(2, inputBase * i);

	return result;
}
//**************************************************************************************
/**
 * Convert number from 2^10 to 2^base
 * @param {!number} value The number to convert
 * @param {!number} base The base for 2^base
 * @param {number} [reserved=0] Pre-defined number of bytes in output array (-1 = limited by function itself)
 * @returns {ArrayBuffer}
 */
export function utilToBase(value, base, reserved = 0)
{
	const internalReserved = reserved || (-1);
	let internalValue = value;

	let result = 0;
	let biggest = Math.pow(2, base);

	for(let i = 1; i < 8; i++)
	{
		if(value < biggest)
		{
			let retBuf;

			if(internalReserved < 0)
			{
				retBuf = new ArrayBuffer(i);
				result = i;
			}
			else
			{
				if(internalReserved < i)
					return (new ArrayBuffer(0));

				retBuf = new ArrayBuffer(internalReserved);

				result = internalReserved;
			}

			const retView = new Uint8Array(retBuf);

			for(let j = (i - 1); j >= 0; j--)
			{
				const basis = Math.pow(2, j * base);

				retView[result - j - 1] = Math.floor(internalValue / basis);
				internalValue -= (retView[result - j - 1]) * basis;
			}

			return retBuf;
		}

		biggest *= Math.pow(2, base);
	}

	return new ArrayBuffer(0);
}
//**************************************************************************************
/**
 * Concatenate two ArrayBuffers
 * @param {...ArrayBuffer} buffers First ArrayBuffer (first part of concatenated array)
 */
export function utilConcatBuf(...buffers)
{
	//region Initial variables
	let outputLength = 0;
	let prevLength = 0;
	//endregion

	//region Calculate output length

	for(const buffer of buffers)
		outputLength += buffer.byteLength;
	//endregion

	const retBuf = new ArrayBuffer(outputLength);
	const retView = new Uint8Array(retBuf);

	for(const buffer of buffers)
	{
		retView.set(new Uint8Array(buffer), prevLength);
		prevLength += buffer.byteLength;
	}

	return retBuf;
}
//**************************************************************************************
/**
 * Decoding of "two complement" values
 * The function must be called in scope of instance of "hexBlock" class ("valueHex" and "warnings" properties must be present)
 * @returns {number}
 */
export function utilDecodeTC()
{
	const buf = new Uint8Array(this.valueHex);

	if(this.valueHex.byteLength >= 2)
	{
		//noinspection JSBitwiseOperatorUsage
		const condition1 = (buf[0] === 0xFF) && (buf[1] & 0x80);
		const condition2 = (buf[0] === 0x00) && ((buf[1] & 0x80) === 0x00);

		if(condition1 || condition2)
			this.warnings.push("Needlessly long format");
	}

	//region Create big part of the integer
	const bigIntBuffer = new ArrayBuffer(this.valueHex.byteLength);
	const bigIntView = new Uint8Array(bigIntBuffer);
	for(let i = 0; i < this.valueHex.byteLength; i++)
		bigIntView[i] = 0;

	bigIntView[0] = (buf[0] & 0x80); // mask only the biggest bit

	const bigInt = utilFromBase(bigIntView, 8);
	//endregion

	//region Create small part of the integer
	const smallIntBuffer = new ArrayBuffer(this.valueHex.byteLength);
	const smallIntView = new Uint8Array(smallIntBuffer);
	for(let j = 0; j < this.valueHex.byteLength; j++)
		smallIntView[j] = buf[j];

	smallIntView[0] &= 0x7F; // mask biggest bit

	const smallInt = utilFromBase(smallIntView, 8);
	//endregion

	return (smallInt - bigInt);
}
//**************************************************************************************
/**
 * Encode integer value to "two complement" format
 * @param {number} value Value to encode
 * @returns {ArrayBuffer}
 */
export function utilEncodeTC(value)
{
	const modValue = (value < 0) ? (value * (-1)) : value;
	let bigInt = 128;

	for(let i = 1; i < 8; i++)
	{
		if(modValue <= bigInt)
		{
			if(value < 0)
			{
				const smallInt = bigInt - modValue;

				const retBuf = utilToBase(smallInt, 8, i);
				const retView = new Uint8Array(retBuf);

				retView[0] |= 0x80;

				return retBuf;
			}

			let retBuf = utilToBase(modValue, 8, i);
			let retView = new Uint8Array(retBuf);

			//noinspection JSBitwiseOperatorUsage
			if(retView[0] & 0x80)
			{
				//noinspection JSCheckFunctionSignatures
				const tempBuf = retBuf.slice(0);
				const tempView = new Uint8Array(tempBuf);

				retBuf = new ArrayBuffer(retBuf.byteLength + 1);
				retView = new Uint8Array(retBuf);

				for(let k = 0; k < tempBuf.byteLength; k++)
					retView[k + 1] = tempView[k];

				retView[0] = 0x00;
			}

			return retBuf;
		}

		bigInt *= Math.pow(2, 8);
	}

	return (new ArrayBuffer(0));
}
//**************************************************************************************
/**
 * Compare two array buffers
 * @param {!ArrayBuffer} inputBuffer1
 * @param {!ArrayBuffer} inputBuffer2
 * @returns {boolean}
 */
export function isEqualBuffer(inputBuffer1, inputBuffer2)
{
	if(inputBuffer1.byteLength !== inputBuffer2.byteLength)
		return false;

	const view1 = new Uint8Array(inputBuffer1);
	const view2 = new Uint8Array(inputBuffer2);

	for(let i = 0; i < view1.length; i++)
	{
		if(view1[i] !== view2[i])
			return false;
	}

	return true;
}
//**************************************************************************************
/**
 * Convert ArrayBuffer into hexdedimal codes
 * @returns {string}
 * @param {!ArrayBuffer} inputBuffer ASN.1 BER encoded array
 * @param {!number} inputOffset Offset in ASN.1 BER encoded array where decoding should be started
 * @param {!number} inputLength Maximum length of array of bytes which can be using in this function
 */
export function toHexCodes(inputBuffer, inputOffset, inputLength)
{
	//region Check input buffer parameters
	if((inputBuffer instanceof ArrayBuffer) === false)
		return "";

	if(inputBuffer.byteLength === 0)
		return "";

	if(inputOffset < 0)
		return "";

	if(inputLength < 0)
		return "";

	if((inputBuffer.byteLength - inputOffset - inputLength) < 0)
		return "";
	//endregion

	let result = "";

	const intBuffer = new Uint8Array(inputBuffer, inputOffset, inputLength);

	for(let i = 0; i < intBuffer.length; i++)
	{
		const str = intBuffer[i].toString(16).toUpperCase();
		result = result + ((str.length === 1) ? " 0" : " ") + str;
	}

	return result;
}
//**************************************************************************************
/**
 * Pad input number with leade "0" if needed
 * @returns {string}
 * @param {number} inputNumber
 * @param {number} fullLength
 */
export function padNumber(inputNumber, fullLength)
{
	const str = inputNumber.toString(10);
	const dif = fullLength - str.length;

	const padding = new Array(dif);
	for(let i = 0; i < dif; i++)
		padding[i] = "0";

	const paddingString = padding.join("");

	return paddingString.concat(str);
}
//**************************************************************************************
const base64Template = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const base64UrlTemplate = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
//**************************************************************************************
/**
 * Encode string into BASE64 (or "base64url")
 * @param {string} input
 * @param {boolean} useUrlTemplate If "true" then output would be encoded using "base64url"
 * @param {boolean} skipPadding Skip BASE-64 padding or not
 * @returns {string}
 */
export function toBase64(input, useUrlTemplate = false, skipPadding = false)
{
	let i = 0;

	let flag1 = 0;
	let flag2 = 0;

	let output = "";

	const template = (useUrlTemplate) ? base64UrlTemplate : base64Template;

	while(i < input.length)
	{
		const chr1 = input.charCodeAt(i++);
		if(i >= input.length)
			flag1 = 1;
		const chr2 = input.charCodeAt(i++);
		if(i >= input.length)
			flag2 = 1;
		const chr3 = input.charCodeAt(i++);

		const enc1 = chr1 >> 2;
		const enc2 = ((chr1 & 0x03) << 4) | (chr2 >> 4);
		let enc3 = ((chr2 & 0x0F) << 2) | (chr3 >> 6);
		let enc4 = chr3 & 0x3F;

		if(flag1 === 1)
			enc3 = enc4 = 64;
		else
		{
			if(flag2 === 1)
				enc4 = 64;
		}

		if(skipPadding)
		{
			if(enc3 === 64)
				output += `${template.charAt(enc1)}${template.charAt(enc2)}`;
			else
			{
				if(enc4 === 64)
					output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}`;
				else
					output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}${template.charAt(enc4)}`;
			}
		}
		else
			output += `${template.charAt(enc1)}${template.charAt(enc2)}${template.charAt(enc3)}${template.charAt(enc4)}`;
	}

	return output;
}
//**************************************************************************************
/**
 * Decode string from BASE64 (or "base64url")
 * @param {string} input
 * @param {boolean} useUrlTemplate If "true" then output would be encoded using "base64url"
 * @returns {string}
 */
export function fromBase64(input, useUrlTemplate = false)
{
	const template = (useUrlTemplate) ? base64UrlTemplate : base64Template;

	//region Aux functions
	function indexof(toSearch)
	{
		for(let i = 0; i < 64; i++)
		{
			if(template.charAt(i) === toSearch)
				return i;
		}

		return 64;
	}

	function test(incoming)
	{
		return ((incoming === 64) ? 0x00 : incoming);
	}
	//endregion

	let i = 0;

	let output = "";

	while(i < input.length)
	{
		const enc1 = indexof(input.charAt(i++));
		const enc2 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));
		const enc3 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));
		const enc4 = (i >= input.length) ? 0x00 : indexof(input.charAt(i++));

		const chr1 = (test(enc1) << 2) | (test(enc2) >> 4);
		const chr2 = ((test(enc2) & 0x0F) << 4) | (test(enc3) >> 2);
		const chr3 = ((test(enc3) & 0x03) << 6) | test(enc4);

		output += String.fromCharCode(chr1);

		if(enc3 !== 64)
			output += String.fromCharCode(chr2);

		if(enc4 !== 64)
			output += String.fromCharCode(chr3);
	}

	return output;
}
//**************************************************************************************
export function arrayBufferToString(buffer)
{
	let resultString = "";
	const view = new Uint8Array(buffer);

	for(const element of view)
		resultString = resultString + String.fromCharCode(element);

	return resultString;
}
//**************************************************************************************
export function stringToArrayBuffer(str)
{
	const stringLength = str.length;

	const resultBuffer = new ArrayBuffer(stringLength);
	const resultView = new Uint8Array(resultBuffer);

	for(let i = 0; i < stringLength; i++)
		resultView[i] = str.charCodeAt(i);

	return resultBuffer;
}
//**************************************************************************************
//endregion
//**************************************************************************************
