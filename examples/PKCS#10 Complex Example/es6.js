/**
 * Created by L on 02.09.16.
 */
import * as asn1js from "asn1js";
import CertificationRequest from "pkijs/src/CertificationRequest";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import Attribute from "pkijs/src/Attribute";
import Extension from "pkijs/src/Extension";
import Extensions from "pkijs/src/Extensions";
import RSAPublicKey from "pkijs/src/RSAPublicKey";
import { getCrypto, getAlgorithmParameters } from "pkijs/src/common";


//*********************************************************************************
// #region Auxiliary functions
//*********************************************************************************
export function formatPEM(pemString)
{
  /// <summary>Format string in order to have each line with length equal to 63</summary>
  /// <param name="pemString" type="String">String to format</param>

  const stringLength = pemString.length;
  let resultString = "";

  for(let i = 0, count = 0; i < stringLength; i++, count++)
  {
    if(count > 63)
    {
      resultString = resultString + "\r\n";
      count = 0;
    }

    resultString = resultString + pemString[i];
  }

  return resultString;
}
//*********************************************************************************
export function arrayBufferToString(buffer)
{
  /// <summary>Create a string from ArrayBuffer</summary>
  /// <param name="buffer" type="ArrayBuffer">ArrayBuffer to create a string from</param>

  let resultString = "";
  let view = new Uint8Array(buffer);

  for(let i = 0; i < view.length; i++)
    resultString = resultString + String.fromCharCode(view[i]);

  return resultString;
}
//*********************************************************************************
export function stringToArrayBuffer(str)
{
  /// <summary>Create an ArrayBuffer from string</summary>
  /// <param name="str" type="String">String to create ArrayBuffer from</param>

  const stringLength = str.length;

  let resultBuffer = new ArrayBuffer(stringLength);
  let resultView = new Uint8Array(resultBuffer);

  for(let i = 0; i < stringLength; i++)
    resultView[i] = str.charCodeAt(i);

  return resultBuffer;
}
//*********************************************************************************
// #endregion
//*********************************************************************************
// #region Create PKCS#10
//*********************************************************************************
export function create_PKCS10()
{
  // #region Initial variables
  let sequence = Promise.resolve();

  const pkcs10 = new CertificationRequest();

  let publicKey;
  let privateKey;

  let hashAlgorithm;
  const hashOption = document.getElementById("hashAlg").value;
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
    default:;
  }

  let signatureAlgorithmName;
  const signOption = document.getElementById("signAlg").value;
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
  // #endregion

  // #region Get a "crypto" extension
  const crypto = getCrypto();
  if(typeof crypto == "undefined")
  {
    alert("No WebCrypto extension found");
    return;
  }
  // #endregion
  // #region Put a static values
  pkcs10.version = 0;
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({ type: "2.5.4.6", value: new asn1js.PrintableString({ value: "RU" }) }));
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({ type: "2.5.4.3", value: new asn1js.Utf8String({ value: "Simple test (простой тест)" }) }));

  pkcs10.attributes = new Array();
  // #endregion

  // #region Create a new key pair
  sequence = sequence.then(() => {
      // #region Get default algorithm parameters for key generation
      const algorithm = getAlgorithmParameters(signatureAlgorithmName, "generatekey");
      if("hash" in algorithm.algorithm)
        algorithm.algorithm.hash.name = hashAlgorithm;
      // #endregion

      return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
    }
  );
  // #endregion

  // #region Store new key in an interim variables
  sequence = sequence.then(keyPair => {
      publicKey = keyPair.publicKey;
      privateKey = keyPair.privateKey;
    },
    function(error)
    {
      alert("Error during key generation: " + error);
    }
  );
  // #endregion

  // #region Exporting public key into "subjectPublicKeyInfo" value of PKCS#10
  sequence = sequence.then(() => pkcs10.subjectPublicKeyInfo.importKey(publicKey));
  // #endregion

  // #region SubjectKeyIdentifier
  sequence = sequence.then(() => {
      return crypto.digest({ name: "SHA-1" }, pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
    }
  ).then(result => {
      pkcs10.attributes.push(new Attribute({
        type: "1.2.840.113549.1.9.14", // pkcs-9-at-extensionRequest
        values: [(new Extensions({
          extensionsArray: [
            new Extension({
              extnID: "2.5.29.14",
              critical: false,
              extnValue: (new asn1js.OctetString({ valueHex: result })).toBER(false)
            })
          ]
        })).toSchema()]
      }));
    }
  );
  // #endregion

  // #region Signing final PKCS#10 request
  sequence = sequence.then(() => pkcs10.sign(privateKey, hashAlgorithm), error => alert("Error during exporting public key: " + error));
  // #endregion

  sequence.then(() => {
      const pkcs10Schema = pkcs10.toSchema();
      const pkcs10Encoded = pkcs10Schema.toBER(false);

      let resultString = "-----BEGIN CERTIFICATE REQUEST-----\r\n";
      resultString = resultString + formatPEM(window.btoa(arrayBufferToString(pkcs10Encoded)));
      resultString = resultString + "\r\n-----END CERTIFICATE REQUEST-----\r\n";

      document.getElementById("pem-text-block").value = resultString;
    }, error => alert("Error signing PKCS#10: " + error));
}
//*********************************************************************************
// #endregion
//*********************************************************************************
// #region Parse existing PKCS#10
//*********************************************************************************
export function parse_PKCS10()
{
  // #region Initial activities
  document.getElementById("pkcs10-subject").innerHTML = "";
  document.getElementById("pkcs10-exten").innerHTML = "";

  document.getElementById("pkcs10-data-block").style.display = "none";
  document.getElementById("pkcs10-attributes").style.display = "none";
  // #endregion

  // #region Decode existing PKCS#10
  const stringPEM = document.getElementById("pem-text-block").value.replace(/(-----(BEGIN|END) CERTIFICATE REQUEST-----|\n)/g, '');

  const asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(stringPEM)));
  const pkcs10 = new CertificationRequest({ schema: asn1.result });
  // #endregion

  // #region Parse and display information about "subject"
  const typemap = {
    "2.5.4.6": "C",
    "2.5.4.11": "OU",
    "2.5.4.10": "O",
    "2.5.4.3": "CN",
    "2.5.4.7": "L",
    "2.5.4.8": "S",
    "2.5.4.12": "T",
    "2.5.4.42": "GN",
    "2.5.4.43": "I",
    "2.5.4.4": "SN",
    "1.2.840.113549.1.9.1": "E-mail"
  };

  for(let i = 0; i < pkcs10.subject.typesAndValues.length; i++)
  {
    let typeval = typemap[pkcs10.subject.typesAndValues[i].type];
    if(typeof typeval === "undefined")
      typeval = pkcs10.subject.typesAndValues[i].type;

    const subjval = pkcs10.subject.typesAndValues[i].value.valueBlock.value;
    const ulrow = "<li><p><span>" + typeval + "</span> " + subjval + "</p></li>";

    document.getElementById("pkcs10-subject").innerHTML = document.getElementById("pkcs10-subject").innerHTML + ulrow;
    if(typeval == "CN")
      document.getElementById("pkcs10-subject-cn").innerHTML = subjval;
  }
  // #endregion

  // #region Put information about public key size
  let publicKeySize = "< unknown >";

  if(pkcs10.subjectPublicKeyInfo.algorithm.algorithmId.indexOf("1.2.840.113549") !== (-1))
  {
    const asn1PublicKey = asn1js.fromBER(pkcs10.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex);
    const rsaPublicKeySimple = new RSAPublicKey({ schema: asn1PublicKey.result });
    let modulusView = new Uint8Array(rsaPublicKeySimple.modulus.valueBlock.valueHex);
    let modulusBitLength = 0;

    if(modulusView[0] === 0x00)
      modulusBitLength = (rsaPublicKeySimple.modulus.valueBlock.valueHex.byteLength - 1) * 8;
    else
      modulusBitLength = rsaPublicKeySimple.modulus.valueBlock.valueHex.byteLength * 8;

    publicKeySize = modulusBitLength.toString();
  }

  document.getElementById("keysize").innerHTML = publicKeySize;
  // #endregion

  // #region Put information about signature algorithm
  const algomap = {
    "1.2.840.113549.1.1.2": "MD2 with RSA",
    "1.2.840.113549.1.1.4": "MD5 with RSA",
    "1.2.840.10040.4.3": "SHA1 with DSA",
    "1.2.840.10045.4.1": "SHA1 with ECDSA",
    "1.2.840.10045.4.3.2": "SHA256 with ECDSA",
    "1.2.840.10045.4.3.3": "SHA384 with ECDSA",
    "1.2.840.10045.4.3.4": "SHA512 with ECDSA",
    "1.2.840.113549.1.1.10": "RSA-PSS",
    "1.2.840.113549.1.1.5": "SHA1 with RSA",
    "1.2.840.113549.1.1.14": "SHA224 with RSA",
    "1.2.840.113549.1.1.11": "SHA256 with RSA",
    "1.2.840.113549.1.1.12": "SHA384 with RSA",
    "1.2.840.113549.1.1.13": "SHA512 with RSA"
  };
  let signatureAlgorithm = algomap[pkcs10.signatureAlgorithm.algorithmId];
  if(typeof signatureAlgorithm === "undefined")
    signatureAlgorithm = pkcs10.signatureAlgorithm.algorithmId;
  else
    signatureAlgorithm = signatureAlgorithm + " (" + pkcs10.signatureAlgorithm.algorithmId + ")";

  document.getElementById("sig-algo").innerHTML = signatureAlgorithm;
  // #endregion

  // #region Put information about PKCS#10 attributes
  if("attributes" in pkcs10)
  {
    for(let i = 0; i < pkcs10.attributes.length; i++)
    {
      const typeval = pkcs10.attributes[i].type;
      let subjval = "";

      for(let j = 0; j < pkcs10.attributes[i].values.length; j++)
      {
        if((pkcs10.attributes[i].values[j] instanceof asn1js.Utf8String) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.BmpString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.UniversalString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.NumericString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.PrintableString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.TeletexString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.VideotexString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.IA5String) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.GraphicString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.VisibleString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.GeneralString) ||
          (pkcs10.attributes[i].values[j] instanceof asn1js.CharacterString))
        {
          subjval = subjval + ((subjval.length === 0) ? "" : ";") + pkcs10.attributes[i].values[j].valueBlock.value;
        }
        else
        {
          subjval = subjval + ((subjval.length === 0) ? "" : ";") + pkcs10.attributes[i].values[j].constructor.blockName();
        }
      }

      const ulrow = "<li><p><span>" + typeval + "</span> " + subjval + "</p></li>";
      document.getElementById("pkcs10-exten").innerHTML = document.getElementById("pkcs10-exten").innerHTML + ulrow;
    }

    document.getElementById("pkcs10-attributes").style.display = "block";
  }
  // #endregion

  document.getElementById("pkcs10-data-block").style.display = "block";
}
//*********************************************************************************
// #endregion
//*********************************************************************************
// #region Verify existing PKCS#10
//*********************************************************************************
export function verify_PKCS10()
{
  // #region Decode existing PKCS#10
  const stringPEM = document.getElementById("pem-text-block").value.replace(/(-----(BEGIN|END) CERTIFICATE REQUEST-----|\n)/g, '');

  const asn1 = asn1js.fromBER(stringToArrayBuffer(window.atob(stringPEM)));
  const pkcs10 = new CertificationRequest({ schema: asn1.result });
  // #endregion

  // #region Verify PKCS#10
  pkcs10.verify().
  then(result => alert("Verification passed: " + result), error => alert("Error during verification: " + error));
  // #endregion
}
//*********************************************************************************
// #endregion
//*********************************************************************************