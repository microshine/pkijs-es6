import { stringToArrayBuffer, arrayBufferToString, bufferToHexCodes } from "pvutils";
import { getCrypto, getAlgorithmParameters } from "pkijs/src/common";
import * as asn1js from "asn1js";
import Certificate from "pkijs/src/Certificate";
import CertificateRevocationList from "pkijs/src/CertificateRevocationList";
import AttributeTypeAndValue from "pkijs/src/AttributeTypeAndValue";
import Time from "pkijs/src/Time";
import RevokedCertificate from "pkijs/src/RevokedCertificate";
import Extension from "pkijs/src/Extension";
import Extensions from "pkijs/src/Extensions";
import PublicKeyInfo from "pkijs/src/PublicKeyInfo";

//*********************************************************************************
let crlBuffer = new ArrayBuffer(0); // ArrayBuffer with loaded or created CRL
let issuerCertificate = null;
let issuerPublicKey = null;
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
      resultString = `${resultString}\r\n`;
      count = 0;
    }
    resultString = resultString + pemString[i];
  }

  return resultString;
}
//*********************************************************************************
function handleFileBrowse(evt) {
  const tempReader = new FileReader();

  const current_files = evt.target.files;

  tempReader.onload = event => {
    crlBuffer = event.target.result;
    parseCRL();
  };

  tempReader.readAsArrayBuffer(current_files[0]);
}
//*********************************************************************************
function handleIssuerCert(evt) {
  const tempReader = new FileReader();

  const current_files = evt.target.files;

  tempReader.onload = event => {
    issuerPublicKey = null;

    const asn1 = asn1js.fromBER(event.target.result);
    issuerCertificate = new Certificate({
      schema: asn1.result
    });
  };

  tempReader.readAsArrayBuffer(current_files[0]);
}
//*********************************************************************************
// #endregion
//*********************************************************************************
// #region Create CRL
//*********************************************************************************
function createCRL(buffer) {
  // #region Initial variables
  let sequence = Promise.resolve();

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
  const crlSimpl = new CertificateRevocationList();

  crlSimpl.version = 1;

  crlSimpl.issuer.typesAndValues.push(new AttributeTypeAndValue({
    type: "2.5.4.6", // Country name
    value: new asn1js.PrintableString({
      value: "RU"
    })
  }));
  crlSimpl.issuer.typesAndValues.push(new AttributeTypeAndValue({
    type: "2.5.4.3", // Common name
    value: new asn1js.BmpString({
      value: "Test"
    })
  }));

  crlSimpl.thisUpdate = new Time({
    type: 0,
    value: new Date()
  });

  const revokedCertificate = new RevokedCertificate({
    userCertificate: new asn1js.Integer({
      value: 999
    }),
    revocationDate: new Time({
      value: new Date()
    }),
    crlEntryExtensions: new Extensions({
      extensions: [new Extension({
        extnID: "2.5.29.21", // cRLReason
        extnValue: (new asn1js.Enumerated({
          value: 1
        })).toBER(false)
      })]
    })
  });

  crlSimpl.revokedCertificates = new Array();
  crlSimpl.revokedCertificates.push(revokedCertificate);
  crlSimpl.crlExtensions = new Extensions({
    extensions: [new Extension({
      extnID: "2.5.29.20", // cRLNumber
      extnValue: (new asn1js.Integer({
        value: 2
      })).toBER(false)
    })]
  });
  // #endregion

  // #region Create a new key pair
  sequence = sequence.then(() => {
    // #region Get default algorithm parameters for key generation
    const algorithm = getAlgorithmParameters(signatureAlgorithmName, "generatekey");
    if ("hash" in algorithm.algorithm) {
      algorithm.algorithm.hash.name = hashAlgorithm;
    }
    // #endregion

    return crypto.generateKey(algorithm.algorithm, true, algorithm.usages);
  });
  // #endregion

  // #region Store new key in an interim variables
  sequence = sequence.then(keyPair => {
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;

    issuerPublicKey = new PublicKeyInfo();
    issuerPublicKey.importKey(publicKey);
  });
  // #endregion

  // #region Signing final CRL
  sequence = sequence.then(() => crlSimpl.sign(privateKey, hashAlgorithm));
  // #endregion

  // #region Encode and store CRL
  sequence = sequence.then(() => {
    crlBuffer = crlSimpl.toSchema(true).toBER(false);

    const crlSimpl_string = String.fromCharCode.apply(null, new Uint8Array(crlBuffer));

    let resultString = "-----BEGIN X509 CRL-----\r\n";
    resultString = resultString + formatPEM(window.btoa(crlSimpl_string));
    resultString = `${resultString}\r\n-----END X509 CRL-----\r\n`;

    document.getElementById("newSignedData").innerHTML = resultString;

    parseCRL();
  });
  // #endregion

  // #region Exporting private key
  sequence = sequence.then(() => crypto.exportKey("pkcs8", privateKey));
  // #endregion

  // #region Store exported key on Web page
  sequence = sequence.then(result => {
    const private_key_string = String.fromCharCode.apply(null, new Uint8Array(result));

    let resultString = document.getElementById("newSignedData").innerHTML;

    resultString = `${resultString}\r\n-----BEGIN PRIVATE KEY-----\r\n`;
    resultString = resultString + formatPEM(window.btoa(private_key_string));
    resultString = `${resultString}\r\n-----END PRIVATE KEY-----\r\n`;

    document.getElementById("newSignedData").innerHTML = resultString;
  });
  // #endregion

  return sequence.catch(e => console.error(e.stack));
}
//*********************************************************************************
// #endregion
//*********************************************************************************
// #region Parse existing CRL
//*********************************************************************************
function parseCRL() {
  // #region Initial check
  if (crlBuffer.byteLength === 0) {
    alert("Nothing to parse");
    return;
  }
  // #endregion

  // #region Initial activities
  document.getElementById("crl-extn-div").style.display = "none";

  const revokedTable = document.getElementById("crl-rev-certs");
  while (revokedTable.rows.length > 1) {
    revokedTable.deleteRow(revokedTable.rows.length - 1);
  }

  const extensionTable = document.getElementById("crl-extn-table");
  while (extensionTable.rows.length > 1) {
    extensionTable.deleteRow(extensionTable.rows.length - 1);
  }

  const issuerTable = document.getElementById("crl-issuer-table");
  while (issuerTable.rows.length > 1) {
    issuerTable.deleteRow(issuerTable.rows.length - 1);
  }
  // #endregion

  // #region Decode existing CRL
  const asn1 = asn1js.fromBER(crlBuffer);
  const crlSimpl = new CertificateRevocationList({
    schema: asn1.result
  });
  // #endregion

  // #region Put information about CRL issuer
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

  for (let i = 0; i < crlSimpl.issuer.typesAndValues.length; i++) {
    let typeval = rdnmap[crlSimpl.issuer.typesAndValues[i].type];
    if (typeof typeval === "undefined") {
      typeval = crlSimpl.issuer.typesAndValues[i].type;
    }

    const subjval = crlSimpl.issuer.typesAndValues[i].value.valueBlock.value;

    const row = issuerTable.insertRow(issuerTable.rows.length);
    const cell0 = row.insertCell(0);
    cell0.innerHTML = typeval;
    const cell1 = row.insertCell(1);
    cell1.innerHTML = subjval;
  }
  // #endregion

  // #region Put information about issuance date
  document.getElementById("crl-this-update").innerHTML = crlSimpl.thisUpdate.value.toString();
  // #endregion

  // #region Put information about expiration date
  if ("nextUpdate" in crlSimpl) {
    document.getElementById("crl-next-update").innerHTML = crlSimpl.nextUpdate.value.toString();
    document.getElementById("crl-next-update-div").style.display = "block";
  }
  // #endregion

  // #region Put information about signature algorithm
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
  };       // array mapping of common algorithm OIDs and corresponding types

  let signatureAlgorithm = algomap[crlSimpl.signature.algorithmId];
  if (typeof signatureAlgorithm === "undefined") {
    signatureAlgorithm = crlSimpl.signature.algorithmId;
  } else {
    signatureAlgorithm = `${signatureAlgorithm} (${crlSimpl.signature.algorithmId})`;
  }

  document.getElementById("crl-sign-algo").innerHTML = signatureAlgorithm;
  // #endregion

  // #region Put information about revoked certificates
  if ("revokedCertificates" in crlSimpl) {
    for (let i = 0; i < crlSimpl.revokedCertificates.length; i++) {
      const row = revokedTable.insertRow(revokedTable.rows.length);
      const cell0 = row.insertCell(0);
      cell0.innerHTML = bufferToHexCodes(crlSimpl.revokedCertificates[i].userCertificate.valueBlock.valueHex);
      const cell1 = row.insertCell(1);
      cell1.innerHTML = crlSimpl.revokedCertificates[i].revocationDate.value.toString();
    }

    document.getElementById("crl-rev-certs-div").style.display = "block";
  }
  // #endregion
  // #region Put information about CRL extensions
  if("crlExtensions" in crlSimpl) {
    for (let i = 0; i < crlSimpl.crlExtensions.extensions.length; i++) {
      const row = extensionTable.insertRow(extensionTable.rows.length);
      const cell0 = row.insertCell(0);
      cell0.innerHTML = crlSimpl.crlExtensions.extensions[i].extnID;
    }

    document.getElementById("crl-extn-div").style.display = "block";
  }
  // #endregion
}
//*********************************************************************************
// #endregion
//*********************************************************************************
// #region Verify existing CRL
//*********************************************************************************
function verifyCRL() {
  // #region Initial check
  if (crlBuffer.byteLength === 0) {
    alert("Nothing to verify");
    return;
  }

  if ((issuerCertificate === null) && (issuerPublicKey === null)) {
    alert("Load CRL's issuer certificate");
    return;
  }
  // #endregion

  // #region Decode existing CRL
  const asn1 = asn1js.fromBER(crlBuffer);
  const crlSimpl = new CertificateRevocationList({
    schema: asn1.result
  });
  // #endregion

  // #region Verify CRL
  const verifyObject = {};

  if (issuerCertificate !== null) {
    verifyObject.issuerCertificate = issuerCertificate;
  }
  if (issuerPublicKey !== null) {
    verifyObject.publicKeyInfo = issuerPublicKey;
  }

  crlSimpl.verify(verifyObject).then(result => {
    alert(`Verification result: ${result}`);
  }, error => {
    alert(`Error during verification: ${error}`);
  });
  // #endregion
}
//*********************************************************************************
// #endregion
//*********************************************************************************
export {createCRL, verifyCRL, handleFileBrowse, handleIssuerCert};
