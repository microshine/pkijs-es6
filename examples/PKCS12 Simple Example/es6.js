import * as asn1js from "asn1js";
import { stringToArrayBuffer, arrayBufferToString } from "pvutils";
import { getCrypto, getAlgorithmParameters, getRandomValues } from "pkijs/src/common";
import Certificate from "pkijs/src/Certificate";
import PrivateKeyInfo from "pkijs/src/PrivateKeyInfo";
import AuthenticatedSafe from "pkijs/src/AuthenticatedSafe";
import SafeContents from "pkijs/src/SafeContents";
import SafeBag from "pkijs/src/SafeBag";
import CertBag from "pkijs/src/CertBag";
import PFX from "pkijs/src/PFX";
import Attribute from "pkijs/src/Attribute";
import PKCS8ShroudedKeyBag from "pkijs/src/PKCS8ShroudedKeyBag";
//*********************************************************************************
//region Global variables
//*********************************************************************************
let certificateBASE64 = "MIIDRDCCAi6gAwIBAgIBATALBgkqhkiG9w0BAQswODE2MAkGA1UEBhMCVVMwKQYD\
        VQQDHiIAUABlAGMAdQBsAGkAYQByACAAVgBlAG4AdAB1AHIAZQBzMB4XDTEzMDEz\
        MTIxMDAwMFoXDTE2MDEzMTIxMDAwMFowODE2MAkGA1UEBhMCVVMwKQYDVQQDHiIA\
        UABlAGMAdQBsAGkAYQByACAAVgBlAG4AdAB1AHIAZQBzMIIBIjANBgkqhkiG9w0B\
        AQEFAAOCAQ8AMIIBCgKCAQEA4qEnCuFxZqTEM/8cYcaYxexT6+fAHan5/eGCFOe1\
        Yxi0BjRuDooWBPX71+hmWK/MKrKpWTpA3ZDeWrQR2WIcaf/ypd6DAEEWWzlQgBYp\
        EUj/o7cykNwIvZReU9JXCbZu0EmeZXzBm1mIcWYRdk17UdneIRUkU379wVJcKXKl\
        gZsx8395UNeOMk11G5QaHzAafQ1ljEKB/x2xDgwFxNaKpSIq3LQFq0PxoYt/PBJD\
        MfUSiWT5cFh1FdKITXQzxnIthFn+NVKicAWBRaSZCRQxcShX6KHpQ1Lmk0/7QoCc\
        DOAmVSfUAaBl2w8bYpnobFSStyY0RJHBqNtnTV3JonGAHwIDAQABo10wWzAMBgNV\
        HRMEBTADAQH/MAsGA1UdDwQEAwIA/zAdBgNVHQ4EFgQU5QmA6U960XL4SII2SEhC\
        cxij0JYwHwYDVR0jBBgwFoAU5QmA6U960XL4SII2SEhCcxij0JYwCwYJKoZIhvcN\
        AQELA4IBAQAikQls3LhY8rYQCZ+8jXrdaRTY3L5J3S2xzoAofkEnQNzNMClaWrZb\
        Y/KQ+gG25MIFwPOWZn/uYUKB2j0yHTRMPEAp/v5wawSqM2BkdnkGP4r5Etx9pe3m\
        og2xNUBqSeopNNto7QgV0o1yYHtuMKQhNAzcFB1CGz25+lXv8VuuU1PoYNrTjipr\
        kjLDgPurNXUjUh9AZl06+Cakoe75LEkuaZKuBQIMNLJFcM2ZSK/QAAaI0E1Dovcs\
        CctW8x/6Qk5fYwNu0jcIdng9dzKYXytzV53+OGxdK5mldyBBkyvTrbO8bWwYT3c+\
        weB1huNpgnpRHJKMz5xVj0bbdnHir6uc";

let privateKeyBASE64 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDioScK4XFmpMQz\
        /xxhxpjF7FPr58Adqfn94YIU57VjGLQGNG4OihYE9fvX6GZYr8wqsqlZOkDdkN5a\
        tBHZYhxp//Kl3oMAQRZbOVCAFikRSP+jtzKQ3Ai9lF5T0lcJtm7QSZ5lfMGbWYhx\
        ZhF2TXtR2d4hFSRTfv3BUlwpcqWBmzHzf3lQ144yTXUblBofMBp9DWWMQoH/HbEO\
        DAXE1oqlIirctAWrQ/Ghi388EkMx9RKJZPlwWHUV0ohNdDPGci2EWf41UqJwBYFF\
        pJkJFDFxKFfooelDUuaTT/tCgJwM4CZVJ9QBoGXbDxtimehsVJK3JjREkcGo22dN\
        XcmicYAfAgMBAAECggEBANMO1fdyIVRAWmE6UspUU+7vuvBWMjruE9126NhjOjAB\
        z5Z/uYdc3kjcdSCMVNR/VBrnrINmlwZBZnL+hCj5EBE/xlDnOwU/mHx4khnXiYOJ\
        glqLwFHcOV+lD3vsxhZLikP8a8GEQCJXbZR+RADzA8gkqJQSxnPkLpqeAyqulKhv\
        iQ2lq2ZxeCXI+iZvURQPTSm86+szClwgzr2uW6NSlNKKeeLHMILed4mrwbPOdyhu\
        tnqvV79GUYH3yYdzbEbbw5GOat77+xPLt33cfLCL7pg5lGDrKEomu6V1d5KmBOhv\
        0K8gGPKfxPrpeUG5n1q58k/2ouCiyAaKWpVoOWmnbzECgYEA/UzAGZ2N8YE+kC85\
        Nl0wQof+WVm+RUDsv6C3L2vPUht3GwnbxSTMl4+NixbCWG46udVhsM2x7ZzYY1eB\
        7LtnBnjvXZTYU4wqZtGR/+X2Rw5ou+oWm16/OgcEuFjP2zpQtr9r/bpKhyBV+IdS\
        ngnLy00RueKGUL6nvtecRklEhQ0CgYEA5Quek+c12qMtrmg5znHPQC7uuieZRzUL\
        9jTlQtuZM5m4B3AfB/N/0qIQS06PHS1ijeHQ9SxEmG72weamUYC0SPi8GxJioFza\
        JEDVit0Ra38gf0CXQvcYT0XD1CwY/m+jDXDWL5L1CCIr60AzNjM3WEfGO4VHaNso\
        vVLn1Fvy5tsCgYEA4ZOEUEubqUOsb8NedCexXs61mOTvKcWUEWQTP0wHqduDyrSQ\
        35TSDvds2j0+fnpMGksJYOcOWcmge3fm4OhT69Ovd+uia2UcLczc9MPa+5S9ePwT\
        ffJ24jp13aZaFaZtUxJOHfvVe1k0tsvsq4mV0EumSaCOdUIVKUPijEWbm9ECgYBp\
        Fa+nxAidSwiGYCNFaEnh9KZqmghk9x2J1DLrPb1IQ1p/bx2NlFYs2VYIdv6KMGxr\
        FBO+qJTAKwjjZWMhOZ99a0FCWmkNkgwzXdubXlnDrAvI1mWPv7ZTiHqUObct5SI1\
        5HMgWJg7JxJnWIkmcNEPm76DSF6+6O4EDql2cMk8yQKBgF5roj+l90lfwImr6V1N\
        Jo3J5VCi9wTT5x9enPY9WRcfSyRjqU7JWy6h0C+Jq+AYAxrkQVjQuv1AOhO8Uhc6\
        amM5FA+gfg5HKKPnwuOe7r7B48LFF8eRjYRtHmrQUrFY0jH6O+t12dEQI+7qE+Sf\
        fUScsZWCREX7QYEK/tuznv/U";
//*********************************************************************************
//endregion 
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
function destroyClickedElement(event)
{
	document.body.removeChild(event.target);
}
//*********************************************************************************
//endregion 
//*********************************************************************************
export function passwordBasedIntegrity(password)
{
	//region Initial variables 
	let sequence = Promise.resolve();
	
	if(typeof password == "undefined")
		password = document.getElementById("password2").value;
	//endregion 
	
	//region Create simplified structires for certificate and private key 
	let asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certificateBASE64)));
	let cert_simpl = new Certificate({ schema: asn1.result });
	
	asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(privateKeyBASE64)));
	let pkcs8_simpl = new PrivateKeyInfo({ schema: asn1.result });
	//endregion 
	
	//region Put initial values for PKCS#12 structures 
	let pkcs12 = new PFX({
		parsedValue: {
			integrityMode: 0, // Password-Based Integrity Mode
			authenticatedSafe: new AuthenticatedSafe({
				parsedValue: {
					safeContents: [
						{
							privacyMode: 0, // "No Privacy" mode
							value: new SafeContents({
								safeBags: [
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.1",
										bagValue: pkcs8_simpl
									}),
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.3",
										bagValue: new CertBag({
											parsedValue: cert_simpl
										})
									})
								]
							})
						}
					]
				}
			})
		}
	});
	//endregion 
	
	//region Encode internal values for all "SafeContents" firts (create all "Privacy Protection" envelopes) 
	sequence = sequence.then(
		() => pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
			safeContents: [
				{
					// Empty parameters since we have "No Privacy" protection level for SafeContents
				}
			]
		})
	);
	//endregion 
	
	//region Encode internal values for "Integrity Protection" envelope 
	sequence = sequence.then(
		() => pkcs12.makeInternalValues({
			password: stringToArrayBuffer(password),
			iterations: 100000,
			pbkdf2HashAlgorithm: "SHA-256", // Least two parameters are equal because at the moment it is not clear how to use PBMAC1 schema with PKCS#12 integrity protection
			hmacHashAlgorithm: "SHA-256"
		})
	);
	//endregion 
	
	//region Save encoded data 
	sequence = sequence.then(
		() => {
			let pkcs12AsBlob = new Blob([pkcs12.toSchema().toBER(false)], { type: 'application/x-pkcs12' });
			let downloadLink = document.createElement("a");
			downloadLink.download = "pkijs_pkcs12.p12";
			downloadLink.innerHTML = "Download File";
			
			downloadLink.href = window.URL.createObjectURL(pkcs12AsBlob);
			downloadLink.onclick = destroyClickedElement;
			downloadLink.style.display = "none";
			document.body.appendChild(downloadLink);
			
			downloadLink.click();
		}
	);
	//endregion 
}
//*********************************************************************************
export function certificateBasedIntegrity()
{
	//region Initial variables 
	let sequence = Promise.resolve();
	//endregion 
	
	//region Create simplified structires for certificate and private key 
	let asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certificateBASE64)));
	let cert_simpl = new Certificate({ schema: asn1.result });
	
	asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(privateKeyBASE64)));
	let pkcs8_simpl = new PrivateKeyInfo({ schema: asn1.result });
	//endregion 
	
	//region Get a "crypto" extension 
	const crypto = getCrypto();
	if(typeof crypto == "undefined")
	{
		alert("No WebCrypto extension found");
		return;
	}
	//endregion 
	
	//region Put initial values for PKCS#12 structures 
	let pkcs12 = new PFX({
		parsedValue: {
			integrityMode: 1, // Certificate-Based Integrity Mode
			authenticatedSafe: new AuthenticatedSafe({
				parsedValue: {
					safeContents: [
						{
							privacyMode: 0, // "No Privacy" mode
							value: new SafeContents({
								safeBags: [
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.1",
										bagValue: pkcs8_simpl
									}),
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.3",
										bagValue: new CertBag({
											parsedValue: cert_simpl
										})
									})
								]
							})
						}
					]
				}
			})
		}
	});
	//endregion 
	
	//region Encode internal values for all "SafeContents" firts (create all "Privacy Protection" envelopes) 
	sequence = sequence.then(
		() => pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
			safeContents: [
				{
					// Empty parameters since we have "No Privacy" protection level for SafeContents
				}
			]
		})
	);
	//endregion 
	
	//region Import PKCS#8 key into WebCrypto key 
	sequence = sequence.then(
		() => cert_simpl.getPublicKey().then(
			result =>{
				let algorithm = getAlgorithmParameters(result.algorithm.name, "importkey");
				
				return crypto.importKey("pkcs8",
					stringToArrayBuffer(window.atob(privateKeyBASE64)),
					algorithm.algorithm,
					true,
					["sign"]);
			}
		)
	);
	//endregion 
	
	//region Encode internal values for "Integrity Protection" envelope 
	sequence = sequence.then(
		result => pkcs12.makeInternalValues({
			signingCertificate: cert_simpl,
			privateKey: result,
			hashAlgorithm: "SHA-256"
		})
	);
	//endregion 
	
	//region Save encoded data 
	sequence = sequence.then(
		() => {
			let pkcs12AsBlob = new Blob([pkcs12.toSchema().toBER(false)], { type: 'application/x-pkcs12' });
			let downloadLink = document.createElement("a");
			downloadLink.download = "pkijs_pkcs12.p12";
			downloadLink.innerHTML = "Download File";
			
			downloadLink.href = window.URL.createObjectURL(pkcs12AsBlob);
			downloadLink.onclick = destroyClickedElement;
			downloadLink.style.display = "none";
			document.body.appendChild(downloadLink);
			
			downloadLink.click();
		}
	);
	//endregion 
}
//*********************************************************************************
export function noPrivacy()
{
	passwordBasedIntegrity(document.getElementById("password3").value); // Same with previous example
}
//*********************************************************************************
export function passwordPrivacy()
{
	//region Initial variables 
	let sequence = Promise.resolve();
	//endregion 
	
	//region Create simplified structires for certificate and private key 
	let asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certificateBASE64)));
	let cert_simpl = new Certificate({ schema: asn1.result });
	
	asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(privateKeyBASE64)));
	let pkcs8_simpl = new PrivateKeyInfo({ schema: asn1.result });
	//endregion 
	
	//region Put initial values for PKCS#12 structures 
	let pkcs12 = new PFX({
		parsedValue: {
			integrityMode: 0, // Password-Based Integrity Mode
			authenticatedSafe: new AuthenticatedSafe({
				parsedValue: {
					safeContents: [
						{
							privacyMode: 1, // Password-Based Privacy Protection Mode
							value: new SafeContents({
								safeBags: [
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.1",
										bagValue: pkcs8_simpl
									}),
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.3",
										bagValue: new CertBag({
											parsedValue: cert_simpl
										})
									})
								]
							})
						}
					]
				}
			})
		}
	});
	//endregion 
	
	//region Encode internal values for all "SafeContents" firts (create all "Privacy Protection" envelopes) 
	sequence = sequence.then(
		() => pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
			safeContents: [
				{
					password: stringToArrayBuffer(document.getElementById("password4").value),
					contentEncryptionAlgorithm: {
						name: "AES-CBC",
						length: 128
					},
					hmacHashAlgorithm: "SHA-256",
					iterationCount: 2048
				}
			]
		})
	);
	//endregion 
	
	//region Encode internal values for "Integrity Protection" envelope 
	sequence = sequence.then(
		() => pkcs12.makeInternalValues({
			password: stringToArrayBuffer(document.getElementById("password4").value),
			iterations: 100000,
			pbkdf2HashAlgorithm: "SHA-256", // Least two parameters are equal because at the moment it is not clear how to use PBMAC1 schema with PKCS#12 integrity protection
			hmacHashAlgorithm: "SHA-256"
		})
	);
	//endregion 
	
	//region Save encoded data 
	sequence = sequence.then(
		() => {
			let pkcs12AsBlob = new Blob([pkcs12.toSchema().toBER(false)], { type: 'application/x-pkcs12' });
			let downloadLink = document.createElement("a");
			downloadLink.download = "pkijs_pkcs12.p12";
			downloadLink.innerHTML = "Download File";
			
			downloadLink.href = window.URL.createObjectURL(pkcs12AsBlob);
			downloadLink.onclick = destroyClickedElement;
			downloadLink.style.display = "none";
			document.body.appendChild(downloadLink);
			
			downloadLink.click();
		}
	);
	//endregion 
}
//*********************************************************************************
export function certificatePrivacy()
{
	//region Initial variables 
	let sequence = Promise.resolve();
	//endregion 
	
	//region Create simplified structires for certificate and private key 
	let asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certificateBASE64)));
	let cert_simpl = new Certificate({ schema: asn1.result });
	
	asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(privateKeyBASE64)));
	let pkcs8_simpl = new PrivateKeyInfo({ schema: asn1.result });
	//endregion 
	
	//region Put initial values for PKCS#12 structures 
	let pkcs12 = new PFX({
		parsedValue: {
			integrityMode: 0, // Password-Based Integrity Mode
			authenticatedSafe: new AuthenticatedSafe({
				parsedValue: {
					safeContents: [
						{
							privacyMode: 2, // Certificate-Based Privacy Protection Mode
							value: new SafeContents({
								safeBags: [
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.1",
										bagValue: pkcs8_simpl
									}),
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.3",
										bagValue: new CertBag({
											parsedValue: cert_simpl
										})
									})
								]
							})
						}
					]
				}
			})
		}
	});
	//endregion 
	
	//region Encode internal values for all "SafeContents" firts (create all "Privacy Protection" envelopes) 
	sequence = sequence.then(
		() => pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
			safeContents: [
				{
					encryptingCertificate: cert_simpl,
					encryptionAlgorithm: {
						name: "AES-CBC",
						length: 128
					}
				}
			]
		})
	);
	//endregion 
	
	//region Encode internal values for "Integrity Protection" envelope 
	sequence = sequence.then(
		() => pkcs12.makeInternalValues({
			password: stringToArrayBuffer(document.getElementById("password5").value),
			iterations: 100000,
			pbkdf2HashAlgorithm: "SHA-256", // Least two parameters are equal because at the moment it is not clear how to use PBMAC1 schema with PKCS#12 integrity protection
			hmacHashAlgorithm: "SHA-256"
		})
	);
	//endregion 
	
	//region Save encoded data 
	sequence = sequence.then(
		() => {
			let pkcs12AsBlob = new Blob([pkcs12.toSchema().toBER(false)], { type: 'application/x-pkcs12' });
			let downloadLink = document.createElement("a");
			downloadLink.download = "pkijs_pkcs12.p12";
			downloadLink.innerHTML = "Download File";
			
			downloadLink.href = window.URL.createObjectURL(pkcs12AsBlob);
			downloadLink.onclick = destroyClickedElement;
			downloadLink.style.display = "none";
			document.body.appendChild(downloadLink);
			
			downloadLink.click();
		}
	);
	//endregion 
}
//*********************************************************************************
export function openSSLLike()
{
	//region Initial variables 
	let sequence = Promise.resolve();
	
	let keyLocalIDBuffer = new ArrayBuffer(4);
	let keyLocalIDView = new Uint8Array(keyLocalIDBuffer);
	
	getRandomValues(keyLocalIDView);
	
	let certLocalIDBuffer = new ArrayBuffer(4);
	let certLocalIDView = new Uint8Array(certLocalIDBuffer);
	
	getRandomValues(certLocalIDView);
	
	//region "KeyUsage" attribute 
	let bit_array = new ArrayBuffer(1);
	let bit_view = new Uint8Array(bit_array);
	
	bit_view[0] = bit_view[0] | 0x80;
	
	let key_usage = new asn1js.BitString({
		valueHex: bit_array,
		unusedBits: 7
	});
	//endregion 
	//endregion 
	
	//region Create simplified structires for certificate and private key 
	let asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(certificateBASE64)));
	let cert_simpl = new Certificate({ schema: asn1.result });
	
	asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(privateKeyBASE64)));
	let pkcs8_simpl = new PrivateKeyInfo({ schema: asn1.result });
	
	//region Add "keyUsage" attribute 
	pkcs8_simpl.attributes = [
		new Attribute({
			type: "2.5.29.15",
			values: [
				key_usage
			]
		})
	];
	//endregion 
	//endregion 
	
	//region Put initial values for PKCS#12 structures 
	let pkcs12 = new PFX({
		parsedValue: {
			integrityMode: 0, // Password-Based Integrity Mode
			authenticatedSafe: new AuthenticatedSafe({
				parsedValue: {
					safeContents: [
						{
							privacyMode: 0, // "No-privacy" Protection Mode
							value: new SafeContents({
								safeBags: [
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.2",
										bagValue: new PKCS8ShroudedKeyBag({
											parsedValue: pkcs8_simpl
										}),
										bagAttributes: [
											new Attribute({
												type: "1.2.840.113549.1.9.20", // friendlyName
												values: [
													new asn1js.BmpString({ value: "PKCS8ShroudedKeyBag from PKIjs" })
												]
											}),
											new Attribute({
												type: "1.2.840.113549.1.9.21", // localKeyID
												values: [
													new asn1js.OctetString({ valueHex: keyLocalIDBuffer })
												]
											}),
											new Attribute({
												type: "1.3.6.1.4.1.311.17.1", // pkcs12KeyProviderNameAttr
												values: [
													new asn1js.BmpString({ value: "http://www.pkijs.org" })
												]
											})
										]
									})
								]
							})
						},
						{
							privacyMode: 1, // Password-Based Privacy Protection Mode
							value: new SafeContents({
								safeBags: [
									new SafeBag({
										bagId: "1.2.840.113549.1.12.10.1.3",
										bagValue: new CertBag({
											parsedValue: cert_simpl
										}),
										bagAttributes: [
											new Attribute({
												type: "1.2.840.113549.1.9.20", // friendlyName
												values: [
													new asn1js.BmpString({ value: "CertBag from PKIjs" })
												]
											}),
											new Attribute({
												type: "1.2.840.113549.1.9.21", // localKeyID
												values: [
													new asn1js.OctetString({ valueHex: certLocalIDBuffer })
												]
											}),
											new Attribute({
												type: "1.3.6.1.4.1.311.17.1", // pkcs12KeyProviderNameAttr
												values: [
													new asn1js.BmpString({ value: "http://www.pkijs.org" })
												]
											})
										]
									})
								]
							})
						}
					]
				}
			})
		}
	});
	//endregion 
	
	//region Encode internal values for "PKCS8ShroudedKeyBag" 
	sequence = sequence.then(
		() => pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.makeInternalValues({
			password: stringToArrayBuffer(document.getElementById("password1").value),
			contentEncryptionAlgorithm: {
				name: "AES-CBC", // OpenSSL can handle AES-CBC only
				length: 128
			},
			hmacHashAlgorithm: "SHA-1", // OpenSSL can handle SHA-1 only
			iterationCount: 100000
		})
	);
	//endregion 
	
	//region Encode internal values for all "SafeContents" firts (create all "Privacy Protection" envelopes) 
	sequence = sequence.then(
		() => pkcs12.parsedValue.authenticatedSafe.makeInternalValues({
			safeContents: [
				{
					// Empty parameters for first SafeContent since "No Privacy" protection mode there
				},
				{
					password: stringToArrayBuffer(document.getElementById("password1").value),
					contentEncryptionAlgorithm: {
						name: "AES-CBC", // OpenSSL can handle AES-CBC only
						length: 128
					},
					hmacHashAlgorithm: "SHA-1", // OpenSSL can handle SHA-1 only
					iterationCount: 100000
				}
			]
		})
	);
	//endregion 
	
	//region Encode internal values for "Integrity Protection" envelope 
	sequence = sequence.then(
		() => pkcs12.makeInternalValues({
			password: stringToArrayBuffer(document.getElementById("password1").value),
			iterations: 100000,
			pbkdf2HashAlgorithm: "SHA-256", // OpenSSL can not handle usage of PBKDF2, only PBKDF1
			hmacHashAlgorithm: "SHA-256"
		})
	);
	//endregion 
	
	//region Save encoded data 
	sequence = sequence.then(
		() => {
			let pkcs12AsBlob = new Blob([pkcs12.toSchema().toBER(false)], { type: 'application/x-pkcs12' });
			let downloadLink = document.createElement("a");
			downloadLink.download = "pkijs_pkcs12.p12";
			downloadLink.innerHTML = "Download File";
			
			downloadLink.href = window.URL.createObjectURL(pkcs12AsBlob);
			downloadLink.onclick = destroyClickedElement;
			downloadLink.style.display = "none";
			document.body.appendChild(downloadLink);
			
			downloadLink.click();
		}
	);
	//endregion 
}
//*********************************************************************************
export function parsePKCS12(buffer)
{
	//region Initial variables 
	let sequence = Promise.resolve();
	//endregion 
	
	//region Parse internal PKCS#12 values 
	let asn1 = asn1js.fromBER(buffer);
	let pkcs12 = new PFX({ schema: asn1.result });
	//endregion 
	
	//region Parse "AuthenticatedSafe" value of PKCS#12 data  
	sequence = sequence.then(
		() => pkcs12.parseInternalValues({
			password: stringToArrayBuffer(document.getElementById("password").value),
			checkIntegrity: false // Do not check an integrity since OpenSSL produce HMAC using old PBKDF1 function
		})
	);
	//endregion 
	
	//region Parse "SafeContents" values 
	sequence = sequence.then(
		() => pkcs12.parsedValue.authenticatedSafe.parseInternalValues({
			safeContents: [
				{
					// Empty parameters since for first "SafeContent" OpenSSL uses "no privacy" protection mode
				},
				{
					password: stringToArrayBuffer(document.getElementById("password").value)
				}
			]
		})
	);
	//endregion 
	
	//region Parse "PKCS8ShroudedKeyBag" value 
	sequence = sequence.then(
		() => pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.parseInternalValues({
			password: stringToArrayBuffer(document.getElementById("password").value)
		})
	);
	//endregion 
	
	//region Store parsed value to Web page 
	sequence = sequence.then(
		() =>{
			//region Initial variables 
			let result = "";
			//endregion 
			
			//region Store X.509 certificate value 
			let certificateBuffer = pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[1].value.safeBags[0].bagValue.parsedValue.toSchema().toBER(false);
			
			result += "-----BEGIN CERTIFICATE-----\r\n";
			result += formatPEM(window.btoa(arrayBufferToString(certificateBuffer)));
			result += "\r\n-----END CERTIFICATE-----\r\n";
			//endregion 
			
			//endregion Store PKCS#8 (private key) value
			let pkcs8Buffer = pkcs12.parsedValue.authenticatedSafe.parsedValue.safeContents[0].value.safeBags[0].bagValue.parsedValue.toSchema().toBER(false);
			
			result += "\r\n-----BEGIN PRIVATE KEY-----\r\n";
			result += formatPEM(window.btoa(arrayBufferToString(pkcs8Buffer)));
			result += "\r\n-----END PRIVATE KEY-----\r\n";
			//endregion 
			
			document.getElementById("parsing_result").innerHTML = result;
		}
	);
	//endregion 
	
}
//*********************************************************************************
export function handlePKCS12(evt)
{
	let temp_reader = new FileReader();
	
	let current_files = evt.target.files;
	
	temp_reader.onload =
		function(event)
		{
			parsePKCS12(event.target.result);
		};
	
	temp_reader.readAsArrayBuffer(current_files[0]);
}
//*********************************************************************************
