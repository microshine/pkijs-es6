import * as asn1js from "asn1js";
import Certificate from "pkijs/src/Certificate";
import { getCrypto, getAlgorithmParameters } from "pkijs/src/common";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import Extension from "pkijs/src/Extension";
import SignedData from "pkijs/src/SignedData";
import EncapsulatedContentInfo from "pkijs/src/EncapsulatedContentInfo";
import ContentInfo from "pkijs/src/ContentInfo";

//*********************************************************************************
// #region Auxiliary functions
//*********************************************************************************
function formatPEM(pemString) {
  /// <summary>Format string in order to have each line with length equal to 63</summary>
  /// <param name="pemString" type="String">String to format</param>
  const stringLength = pemString.length;
  let resultString = "";
  for (let i = 0, count = 0; i < stringLength; i++, count++) {
    if (count > 63) {
      resultString = resultString + "\r\n";
      count = 0;
    }
    resultString = resultString + pemString[i];
  }
  return resultString;
}
//*********************************************************************************
function arrayBufferToString(buffer) {
  /// <summary>Create a string from ArrayBuffer</summary>
  /// <param name="buffer" type="ArrayBuffer">ArrayBuffer to create a string from</param>
  let resultString = "";
  let view = new Uint8Array(buffer);
  for (let i = 0; i < view.length; i++)
    resultString = resultString + String.fromCharCode(view[i]);
  return resultString;
}
//*********************************************************************************
function stringToArrayBuffer(str) {
  /// <summary>Create an ArrayBuffer from string</summary>
  /// <param name="str" type="String">String to create ArrayBuffer from</param>
  const stringLength = str.length;
  let resultBuffer = new ArrayBuffer(stringLength);
  let resultView = new Uint8Array(resultBuffer);
  for (let i = 0; i < stringLength; i++)
    resultView[i] = str.charCodeAt(i);
  return resultBuffer;
}
//*********************************************************************************
// #endregion
//*********************************************************************************
// #region Create P7B Data
//*********************************************************************************
function createP7B() {
  // #region Initial variables
  let sequence = Promise.resolve();
  const certSimpl = new Certificate();
  let publicKey;
  let privateKey;
  let hashAlgorithm;
  const hashOption = document.getElementById("hashAlg").value;
  switch (hashOption) {
    case "algSHA1":
      hashAlgorithm = "sha-1";
      break;
    case "algSHA256":
      hashAlgorithm = "sha-256";
      break;
    case "algSHA384":
      hashAlgorithm = "sha-384";
      break;
    case "algSHA512":
      hashAlgorithm = "sha-512";
      break;
    default:;
  }
  let signatureAlgorithmName;
  const signOption = document.getElementById("signAlg").value;
  switch (signOption) {
    case "algRSA15":
      signatureAlgorithmName = "RSASSA-PKCS1-V1_5";
      break;
    case "algRSA2":
      signatureAlgorithmName = "RSA-PSS";
      break;
    case "algECDSA":
      signatureAlgorithmName = "ECDSA";
      break;
    default:;
  }
  // #endregion
  // #region Get a "crypto" extension
  const crypto = getCrypto();
  if (typeof crypto == "undefined") {
    alert("No WebCrypto extension found");
    return;
  }
  // #endregion
  // #region Put a static values
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
  certSimpl.notBefore.value = new Date(2013, 0, 1);
  certSimpl.notAfter.value = new Date(2016, 0, 1);
  certSimpl.extensions = new Array(); // Extensions are not a part of certificate by default, it's an optional array
  // #region "KeyUsage" extension
  let bitArray = new ArrayBuffer(1);
  let bitView = new Uint8Array(bitArray);
  bitView[0] = bitView[0] | 0x02; // Key usage "cRLSign" flag
  //bitView[0] = bitView[0] | 0x04; // Key usage "keyCertSign" flag
  const keyUsage = new asn1js.BitString({ valueHex: bitArray });
  certSimpl.extensions.push(new Extension({
    extnID: "2.5.29.15",
    critical: false,
    extnValue: keyUsage.toBER(false),
    parsedValue: keyUsage // Parsed value for well-known extensions
  }));
  // #endregion
  // #endregion
  // #region Create a new key pair
  sequence = sequence.then(() => {
    // #region Get default algorithm parameters for key generation
    let algorithm = getAlgorithmParameters(signatureAlgorithmName, "generatekey");
    if ("hash" in algorithm.algorithm)
      algorithm.algorithm.hash.name = hashAlgorithm;
    // #endregion
    return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
  });
  // #endregion
  // #region Store new key in an interim variables
  sequence = sequence.then((keyPair) => {
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
  });
  // #endregion
  // #region Exporting public key into "subjectPublicKeyInfo" value of certificate
  sequence = sequence.then(() => certSimpl.subjectPublicKeyInfo.importKey(publicKey));
  // #endregion
  // #region Signing final certificate
  sequence = sequence.then(() => certSimpl.sign(privateKey, hashAlgorithm));
  // #endregion
  sequence = sequence.then(() => {
    const cmsSignedSimpl = new SignedData({
      version: 1,
      encapContentInfo: new EncapsulatedContentInfo({
        eContentType: "1.2.840.113549.1.7.1" // "data" content type
      }),
      certificates: [
        certSimpl,
        certSimpl,
        certSimpl
      ] // Put 3 copies of the same X.509 certificate
    });
    let cmsSignedSchema = cmsSignedSimpl.toSchema(true);
    const cmsContentSimp = new ContentInfo({
      contentType: "1.2.840.113549.1.7.2",
      content: cmsSignedSchema
    });
    cmsSignedSchema = cmsContentSimp.toSchema(true);
    let cmsSignedBuffer = cmsSignedSchema.toBER(false);
    // #region Convert ArrayBuffer to String
    let signedDataString = "";
    let view = new Uint8Array(cmsSignedBuffer);
    for (let i = 0; i < view.length; i++)
      signedDataString = signedDataString + String.fromCharCode(view[i]);
    // #endregion
    let resultString = document.getElementById("newSignedData").innerHTML;
    resultString = "\r\n-----BEGIN CMS-----\r\n";
    resultString = resultString + formatPEM(window.btoa(signedDataString));
    resultString = resultString + "\r\n-----END CMS-----\r\n\r\n";
    document.getElementById("newSignedData").innerHTML = resultString;
  });

  return sequence.catch((e) => console.error(e.stack));
}
//*********************************************************************************
// #endregion
//*********************************************************************************
export {createP7B};